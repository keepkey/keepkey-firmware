/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2022 markrypto <cryptoakorn@gmail.com>
 * Copyright (C) 2016 Alex Beregszaszi <alex@rtfs.hu>
 * Copyright (C) 2016 Pavol Rusnak <stick@satoshilabs.com>
 * Copyright (C) 2016 Jochen Hoenicke <hoenicke@gmail.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "keepkey/firmware/ethereum.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/app_confirm.h"
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/crypto.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/eip712.h"
#include "keepkey/firmware/ethereum_contracts.h"
#include "keepkey/firmware/erc7730_workflow.h"
#include "keepkey/firmware/ethereum_contracts/makerdao.h"
#include "keepkey/firmware/ethereum_contracts/thortx.h"
#include "keepkey/firmware/signed_metadata.h"
#include "keepkey/firmware/contact_book.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/thorchain.h"
#include "keepkey/firmware/tiny-json.h"
#include "keepkey/firmware/transaction.h"
#include "trezor/crypto/address.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/sha3.h"

#include <stdio.h>

#define _(X) (X)

bool ethereum_typed_hash_policy_allows(bool advanced_mode) {
  return advanced_mode;
}

/* The device-driven stream validates, renders and hashes each leaf from the
 * same byte buffer. It is not blind signing and therefore does not inherit the
 * AdvancedMode requirement of the precomputed-hash endpoint. */
bool ethereum_streamed_eip712_enabled(void) { return true; }

/* The legacy JSON parser cannot guarantee that every displayed value is the
 * canonical value hashed by EIP-712. Keep the protocol symbol for compatibility
 * but fail closed in the FSM until the complete parser hardening is backported.
 */
bool ethereum_structured_eip712_enabled(void) { return false; }

/* The EIP-155 legacy recovery id is v + 2 * chain_id + 35, computed below in
 * a uint32_t, where v is 0 or 1. The bound is the largest chain id whose
 * WORST case still fits:
 *
 *     2 * 2147483629 + 35 + 1 == 4294967294   <= UINT32_MAX, fits
 *     2 * 2147483630 + 35 + 1 == 4294967296   wraps to 0
 *
 * The old bound of 2147483630 sat exactly on that wrap: with v == 0 it lands
 * on UINT32_MAX, and with v == 1 it reports a recovery id of 0 for a signature
 * the device really made. A verifier recovers the wrong address from that, so
 * the signature is silently unverifiable rather than refused. */
#define MAX_CHAIN_ID 2147483629

#define ETHEREUM_TX_TYPE_LEGACY 0UL
#define ETHEREUM_TX_TYPE_EIP_2930 1UL
#define ETHEREUM_TX_TYPE_EIP_1559 2UL

#if ETHEREUM_CONFIRM_BODY_SIZE != BODY_CHAR_MAX
#error "Ethereum confirmation capacity must match the confirmation renderer"
#endif

static bool ethereum_signing = false;
static uint32_t data_total, data_left;
/* Arbitrary calldata may continue across EthereumTxAck messages. Track a
 * second Keccak state whose sole input is calldata so the final approval can
 * bind to every byte, not merely the first chunk or the whole RLP preimage. */
static bool data_hash_pending = false;
static struct SHA3_CTX data_keccak_ctx;
static EthereumTxRequest msg_tx_request;
static CONFIDENTIAL uint8_t privkey[32];
static uint32_t chain_id;
static uint32_t wanchain_tx_type;  // Wanchain only
static uint32_t
    ethereum_tx_type;  // Ethereum tx type (0=Legacy, 1=EIP-2930, 2=EIP-1559)
struct SHA3_CTX keccak_ctx;

bool ethereum_chainIdIsValid(const EthereumSignTx* msg) {
  return msg && msg->has_chain_id && msg->chain_id >= 1 &&
         msg->chain_id <= MAX_CHAIN_ID;
}

/* Classification can run before signing_init canonicalizes the RLP value. */
bool ethereum_valueIsZero(const EthereumSignTx* msg) {
  if (!msg->has_value) return true;
  for (size_t i = 0; i < msg->value.size; ++i) {
    if (msg->value.bytes[i] != 0) return false;
  }
  return true;
}

bool ethereum_isStandardERC20Transfer(const EthereumSignTx* msg) {
  if (msg->has_to && msg->to.size == 20 && ethereum_valueIsZero(msg) &&
      msg->data_initial_chunk.size == 68 &&
      memcmp(msg->data_initial_chunk.bytes,
             "\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
             16) == 0) {
    return true;
  }
  return false;
}

/* The chain id is signed, and the amount screens cannot tell chains apart:
 * Ethereum, Optimism, Base and Arbitrum all read "ETH", and every chain
 * without an entry reads "Wei". So the last screen's title names the chain.
 * Mainnet, and a legacy transaction with no chain id, keep "Transaction". */
void ethereum_transactionTitle(const EthereumSignTx* msg, char* title,
                               size_t title_len) {
  static const struct {
    uint32_t chain_id;
    const char* name;
  } chains[] = {{10, "Optimism"},    {56, "BNB Chain"}, {100, "Gnosis"},
                {137, "Polygon"},    {8453, "Base"},    {42161, "Arbitrum"},
                {43114, "Avalanche"}};
  if (!msg->has_chain_id || msg->chain_id == 0 || msg->chain_id == 1) {
    strlcpy(title, "Transaction", title_len);
    return;
  }
  for (size_t i = 0; i < sizeof(chains) / sizeof(chains[0]); i++) {
    if (chains[i].chain_id == msg->chain_id) {
      snprintf(title, title_len, "Tx on %s", chains[i].name);
      return;
    }
  }
  snprintf(title, title_len, "Tx on chain %" PRIu32, msg->chain_id);
}

static bool ethereum_isERC20ApproveCall(const EthereumSignTx* msg) {
  if (msg->has_to && msg->to.size == 20 && msg->data_initial_chunk.size >= 68 &&
      memcmp(msg->data_initial_chunk.bytes,
             "\x09\x5e\xa7\xb3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
             16) == 0) {
    return true;
  }
  return false;
}

/* approve(spender, amount) and increaseAllowance(spender, amount) share a
 * layout and either can grant everything, so the allowance policy covers
 * both. len < 4 matches a selector prefix. */
static bool ethereum_isAllowanceSelector(const uint8_t* data, size_t len) {
  return memcmp(data, "\x09\x5e\xa7\xb3", len) == 0 ||
         memcmp(data, "\x39\x50\x93\x51", len) == 0;
}

/* Both ABI words present, and nothing in the spender word's high bytes. */
static bool ethereum_allowanceIsWellFormed(const EthereumSignTx* msg) {
  if (msg->data_initial_chunk.size < 68) return false;
  for (size_t i = 4; i < 16; ++i)
    if (msg->data_initial_chunk.bytes[i] != 0) return false;
  return true;
}

/* ERC-7730's threshold: an allowance of 2^255 or more is UNLIMITED. */
static bool ethereum_allowanceIsUnlimited(const EthereumSignTx* msg) {
  return (msg->data_initial_chunk.bytes[36] & 0x80) != 0;
}

/* An unlimited approve signs only after this warning, with the full spender
 * and the token named by symbol, or by contract when the table lacks it. */
bool ethereum_confirmUnlimitedApproval(uint32_t cid,
                                       const uint8_t* spender_address,
                                       const uint8_t* token_address) {
  char spender[43] = "0x";
  ethereum_address_checksum(spender_address, spender + 2, false, cid);
  char asset[43] = "0x";
  const TokenType* token = tokenByChainAddress(cid, token_address);
  if (token != UnknownToken) {
    strlcpy(asset, token->ticker + 1, sizeof(asset));
  } else {
    ethereum_address_checksum(token_address, asset + 2, false, cid);
  }
  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "UNLIMITED approval", "Allow %s to spend ALL your %s", spender,
                 asset);
}

bool ethereum_isStandardERC20Approve(const EthereumSignTx* msg) {
  return ethereum_valueIsZero(msg) && msg->data_initial_chunk.size == 68 &&
         ethereum_isERC20ApproveCall(msg);
}

bool ethereum_getStandardERC20Recipient(const EthereumSignTx* msg,
                                        char* address, size_t len) {
  if (len < 2 * 20 + 1) return false;

  data2hex(msg->data_initial_chunk.bytes + 16, 20, address);
  return true;
}

bool ethereum_getStandardERC20Coin(const EthereumSignTx* msg, CoinType* coin) {
  const CoinType* found =
      coinByChainAddress(msg->has_chain_id ? msg->chain_id : 1, msg->to.bytes);
  if (found) {
    memcpy(coin, found, sizeof(*coin));
    return true;
  }

  const TokenType* token =
      tokenByChainAddress(msg->has_chain_id ? msg->chain_id : 1, msg->to.bytes);
  if (token == UnknownToken) return false;

  coinFromToken(coin, token);
  return true;
}

bool ethereumFormatTransferAmount(const EthereumSignTx* msg, char* buf,
                                  int buflen) {
  if (!msg || !buf || buflen <= 0 || !ethereum_chainIdIsValid(msg)) {
    return false;
  }

  const uint8_t* value_bytes;
  size_t value_size;
  const TokenType* token;

  /* ethereumFormatAmount() keys the " WAN" ticker off the module's
   * wanchain_tx_type, which ethereum_signing_init() sets -- and on the
   * transfer path that has not run yet. Set it from THIS message, or a
   * previous Wanchain transaction's type names the asset on this one's amount
   * screen. signing_init() assigns the same value again later. */
  wanchain_tx_type =
      (msg->has_tx_type && (msg->tx_type == 1 || msg->tx_type == 6))
          ? msg->tx_type
          : 0;

  if (ethereum_isStandardERC20Transfer(msg)) {
    value_bytes = msg->data_initial_chunk.bytes + 4 + 32;
    value_size = 32;
    token = tokenByChainAddress(msg->chain_id, msg->to.bytes);
    if (token == UnknownToken) return false;
  } else {
    value_bytes = msg->value.bytes;
    value_size = msg->value.size;
    token = NULL;
  }

  bignum256 value;
  bn_from_bytes(value_bytes, value_size, &value);
  return ethereumFormatAmount(&value, token, msg->chain_id, buf, buflen);
}

void bn_from_bytes(const uint8_t* value, size_t value_len, bignum256* val) {
  uint8_t pad_val[32];
  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - value_len), value, value_len);
  bn_read_be(pad_val, val);
  memzero(pad_val, sizeof(pad_val));
}

bool ethereumFormatUnknownTokenReview(const EthereumSignTx* msg, char* buf,
                                      size_t buflen) {
  if (msg == NULL || buf == NULL || buflen == 0 || !msg->has_to ||
      msg->to.size != 20 || msg->data_initial_chunk.size != 68 ||
      (!ethereum_isStandardERC20Transfer(msg) &&
       !ethereum_isStandardERC20Approve(msg))) {
    return false;
  }

  char contract[43] = "0x";
  char counterparty[43] = "0x";
  ethereum_address_checksum(msg->to.bytes, contract + 2, false, msg->chain_id);
  ethereum_address_checksum(msg->data_initial_chunk.bytes + 16,
                            counterparty + 2, false, msg->chain_id);

  const bool approve = ethereum_isStandardERC20Approve(msg);
  bignum256 raw_value;
  bn_from_bytes(msg->data_initial_chunk.bytes + 36, 32, &raw_value);
  const bool unlimited = approve && ethereum_allowanceIsUnlimited(msg);
  char amount[96];
  if (unlimited) {
    strlcpy(amount, "UNLIMITED", sizeof(amount));
  } else if (bn_format(&raw_value, NULL, " base units", 0, 0, false, amount,
                       sizeof(amount)) == 0) {
    return false;
  }

  const int written =
      approve
          ? snprintf(buf, buflen,
                     "Unknown token contract %s\nAllow %s to withdraw up to "
                     "%s?",
                     contract, counterparty, amount)
          : snprintf(buf, buflen, "Unknown token contract %s\nSend %s to %s?",
                     contract, amount, counterparty);
  return written >= 0 && (size_t)written < buflen;
}

static inline void hash_data(const uint8_t* buf, size_t size) {
  sha3_Update(&keccak_ctx, buf, size);
}

/*
 * Push an RLP encoded length to the hash buffer.
 */
static void hash_rlp_length(uint32_t length, uint8_t firstbyte) {
  uint8_t buf[4];
  if (length == 1 && firstbyte <= 0x7f) {
    /* empty length header */
  } else if (length <= 55) {
    buf[0] = 0x80 + length;
    hash_data(buf, 1);
  } else if (length <= 0xff) {
    buf[0] = 0xb7 + 1;
    buf[1] = length;
    hash_data(buf, 2);
  } else if (length <= 0xffff) {
    buf[0] = 0xb7 + 2;
    buf[1] = length >> 8;
    buf[2] = length & 0xff;
    hash_data(buf, 3);
  } else {
    buf[0] = 0xb7 + 3;
    buf[1] = length >> 16;
    buf[2] = length >> 8;
    buf[3] = length & 0xff;
    hash_data(buf, 4);
  }
}

/*
 * Push an RLP encoded list length to the hash buffer.
 */
static void hash_rlp_list_length(uint32_t length) {
  uint8_t buf[4];
  if (length <= 55) {
    buf[0] = 0xc0 + length;
    hash_data(buf, 1);
  } else if (length <= 0xff) {
    buf[0] = 0xf7 + 1;
    buf[1] = length;
    hash_data(buf, 2);
  } else if (length <= 0xffff) {
    buf[0] = 0xf7 + 2;
    buf[1] = length >> 8;
    buf[2] = length & 0xff;
    hash_data(buf, 3);
  } else {
    buf[0] = 0xf7 + 3;
    buf[1] = length >> 16;
    buf[2] = length >> 8;
    buf[3] = length & 0xff;
    hash_data(buf, 4);
  }
}

/*
 * Push an RLP encoded length field and data to the hash buffer.
 */
static void hash_rlp_field(const uint8_t* buf, size_t size) {
  hash_rlp_length(size, size ? buf[0] : 0);
  hash_data(buf, size);
}

/*
 * Push an RLP encoded number to the hash buffer.
 * Ethereum yellow paper says to convert to big endian and strip leading zeros.
 */
static void hash_rlp_number(uint32_t number) {
  if (!number) {
    return;
  }
  uint8_t data[4];
  data[0] = (number >> 24) & 0xff;
  data[1] = (number >> 16) & 0xff;
  data[2] = (number >> 8) & 0xff;
  data[3] = (number) & 0xff;
  int offset = 0;
  while (!data[offset]) {
    offset++;
  }
  hash_rlp_field(data + offset, 4 - offset);
}

/* Strip leading zero bytes before RLP-encoding an integer field.
 * Per the Ethereum yellow paper, integer fields (nonce, gas, value, etc.)
 * must not have leading zeros. Addresses are NOT integers and must not use
 * this function. */
static void hash_rlp_bytes_stripped(const uint8_t* buf, size_t size) {
  size_t offset = 0;
  while (offset < size && buf[offset] == 0) offset++;
  if (offset == size) {
    hash_rlp_field(buf, 0);
  } else {
    hash_rlp_field(buf + offset, size - offset);
  }
}

/*
 * Calculate the number of bytes needed for an RLP length header.
 * NOTE: supports up to 16MB of data (how unlikely...)
 * FIXME: improve
 */
static int rlp_calculate_length(int length, uint8_t firstbyte) {
  if (length == 1 && firstbyte <= 0x7f) {
    return 1;
  } else if (length <= 55) {
    return 1 + length;
  } else if (length <= 0xff) {
    return 2 + length;
  } else if (length <= 0xffff) {
    return 3 + length;
  } else {
    return 4 + length;
  }
}

/* Length of an RLP-encoded integer field AFTER stripping leading zero bytes.
 * MUST mirror hash_rlp_bytes_stripped(): the Stage-1 list-length header
 * (hash_rlp_list_length) and the Stage-2 bytes actually hashed have to agree,
 * or the keccak pre-image is malformed and the signature recovers to a garbage
 * address (looks like a "random signer" / dropped tx). Any integer field whose
 * big-endian form has a leading zero byte hits this. */
static int rlp_calculate_length_stripped(const uint8_t* buf, size_t size) {
  size_t offset = 0;
  while (offset < size && buf[offset] == 0) offset++;
  if (offset == size) {
    return rlp_calculate_length(0, 0);
  }
  return rlp_calculate_length(size - offset, buf[offset]);
}

static int rlp_calculate_number_length(uint32_t number) {
  if (number <= 0x7f) {
    return 1;
  } else if (number <= 0xff) {
    return 2;
  } else if (number <= 0xffff) {
    return 3;
  } else if (number <= 0xffffff) {
    return 4;
  } else {
    return 5;
  }
}

static void send_request_chunk(void) {
  /* The previous chunk was validated and hashed before requesting more. */
  note_workflow_progress();
  layoutProgress(_("Signing"), (data_total - data_left) * 1000 / data_total);
  msg_tx_request.has_data_length = true;
  msg_tx_request.data_length = data_left <= 1024 ? data_left : 1024;
  msg_write(MessageType_MessageType_EthereumTxRequest, &msg_tx_request);
}

static int ethereum_is_canonic(uint8_t v, uint8_t signature[64]) {
  (void)signature;
  return (v & 2) == 0;
}

static void send_signature(void) {
  uint8_t hash[32], sig[64];
  uint8_t v;
  layoutProgress(_("Signing"), 1000);

  const Erc7730Workflow* const erc7730 = erc7730_workflow_state();
  if (erc7730->phase != ERC7730_WORKFLOW_IDLE &&
      !erc7730_workflow_complete(erc7730)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    "ERC-7730 calldata verification incomplete");
    ethereum_signing_abort();
    return;
  }

  if (ethereum_tx_type == ETHEREUM_TX_TYPE_LEGACY) {
    /* legacy eip-155 replay protection */
    if (chain_id) {
      /* hash v=chain_id, r=0, s=0 */
      hash_rlp_number(chain_id);
      hash_rlp_length(0, 0);
      hash_rlp_length(0, 0);
    }
  }

  keccak_Final(&keccak_ctx, hash);

  /* Insight clear-signing binding. Metadata is additive: the raw-data review
   * still happens, and approved decoded screens are shown on top of it. When
   * the user approved such screens, the actual signed digest MUST equal the tx
   * hash the metadata committed to. This is the first point that digest
   * exists, so the check reuses it rather than re-deriving the RLP pre-image.
   * Fail closed -- never sign what the approved decoded screens did not
   * cover. */
  if (!signed_metadata_enforce(hash)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    "Metadata does not match signed transaction");
    ethereum_signing_abort();
    memzero(hash, sizeof(hash));
    return;
  }

  if (ecdsa_sign_digest(&secp256k1, privkey, hash, sig, &v,
                        ethereum_is_canonic) != 0) {
    fsm_sendFailure(FailureType_Failure_Other, "Signing failed");
    ethereum_signing_abort();
    return;
  }

  memzero(privkey, sizeof(privkey));

  /* Send back the result */
  msg_tx_request.has_data_length = false;

  msg_tx_request.has_signature_v = true;
  if (chain_id > MAX_CHAIN_ID ||
      ethereum_tx_type == ETHEREUM_TX_TYPE_EIP_1559) {
    msg_tx_request.signature_v = v;
  } else if (chain_id) {
    msg_tx_request.signature_v = v + 2 * chain_id + 35;
  } else {
    msg_tx_request.signature_v = v + 27;
  }

  msg_tx_request.has_signature_r = true;
  msg_tx_request.signature_r.size = 32;
  memcpy(msg_tx_request.signature_r.bytes, sig, 32);

  msg_tx_request.has_signature_s = true;
  msg_tx_request.signature_s.size = 32;
  memcpy(msg_tx_request.signature_s.bytes, sig + 32, 32);

  // KeepKey custom (for the KeepKey Client)
  msg_tx_request.has_hash = true;
  msg_tx_request.hash.size = sizeof(msg_tx_request.hash.bytes);
  memcpy(msg_tx_request.hash.bytes, hash, msg_tx_request.hash.size);
  msg_tx_request.has_signature_der = true;
  msg_tx_request.signature_der.size =
      ecdsa_sig_to_der(sig, msg_tx_request.signature_der.bytes);

  msg_write(MessageType_MessageType_EthereumTxRequest, &msg_tx_request);

  ethereum_signing_abort();
}

/* For EIP-1559 the empty access list (`0xC0`) closes the RLP body and MUST
 * be the last byte fed to keccak before signing. Hashing it earlier — e.g.
 * right after `data_initial_chunk` in `ethereum_signing_init` — would
 * sandwich it between data chunks whenever `data_total > 1024`, producing a
 * non-canonical pre-image whose signature recovers to a wrong-but-
 * deterministic address (looks like a "malformed sig" / dropped tx).
 * Call this helper from every `send_signature()` call site instead.
 */
static void finalize_eip1559_and_send_signature(void) {
  if (ethereum_tx_type == ETHEREUM_TX_TYPE_EIP_1559) {
    uint8_t datbuf[1] = {0xC0}; /* empty access list (0-length list) */
    hash_data(datbuf, sizeof(datbuf));
  }
  send_signature();
}

/* Format a 256 bit number (amount in wei) into a human readable format
 * using standard ethereum units.
 * The buffer must be at least 28 bytes so the overflow sentinel always fits.
 */
bool ethereumFormatAmount(const bignum256* amnt, const TokenType* token,
                          uint32_t cid, char* buf, int buflen) {
  bignum256 bn1e9;
  bn_read_uint32(1000000000, &bn1e9);
  const char* suffix = NULL;
  int decimals = 18;
  if (token == UnknownToken) {
    strlcpy(buf, "Unknown token value", buflen);
    return true;
  } else if (token != NULL) {
    suffix = token->ticker;
    decimals = token->decimals;
  } else if (bn_is_less(amnt, &bn1e9)) {
    suffix = " Wei";
    decimals = 0;
  } else {
    if (wanchain_tx_type == 1 || wanchain_tx_type == 6) {
      suffix = " WAN";
    } else {
      // constants from trezor-common/defs/ethereum/networks.json
      switch (cid) {
        case 1:
          suffix = " ETH";
          break;  // Ethereum
        case 2:
          suffix = " EXP";
          break;  // Expanse
        case 8:
          suffix = " UBQ";
          break;  // UBIQ
        case 10:
          suffix = " ETH";
          break;  // Optimism
        case 20:
          suffix = " EOSC";
          break;  // EOS Classic
        case 28:
          suffix = " ETSC";
          break;  // Ethereum Social
        case 30:
          suffix = " RBTC";
          break;  // Rootstock
        case 40:
          suffix = " TLOS";
          break;  // Telos
        case 56:
          suffix = " BNB";
          break;  // BNB Chain
        case 61:
          suffix = " ETC";
          break;  // Ethereum Classic
        case 64:
          suffix = " ELLA";
          break;  // Ellaism
        case 100:
          suffix = " xDAI";
          break;  //  Gnosis Chain
        case 137:
          suffix = " MATIC";
          break;  //  Polygon Mainnet
        case 8453:
          suffix = " ETH";
          break;  // Base
        case 42161:
          suffix = " ETH";
          break;  // Arbitrum One
        case 43114:
          suffix = " AVAX";
          break;  // Avalanche C-Chain
      }

      /* No case matched: this chain's native asset has no name here.
       *
       * Falling through with suffix == NULL made bn_format() render a bare
       * 18-decimal number -- "Send 0.05 to 0xABC" -- which names no asset and
       * no network, on a screen that is the whole basis for the signature.
       * Both the value and the gas fee go through this function with
       * token == NULL, so an unmapped chain got two unlabelled numbers.
       *
       * Adding more cases does not fix this; the fallback has to stop being
       * silent. Refusing is not right either: every caller treats false as a
       * hard refusal, so a chain merely missing from this list -- a new L2,
       * say -- would become unsignable, including its gas.
       *
       * So state exactly what is known. Wei is the base unit of every EVM
       * chain regardless of what its native asset is called, so the amount
       * stays exact and carries a correct unit; what is dropped is the claim
       * to know the asset's name. This is the same rendering sub-gwei amounts
       * already get a few lines above. */
      if (!suffix) {
        suffix = " Wei";
        decimals = 0;
      }
    }
  }
  /* bn_format() BLANKS the buffer and returns 0 when the value does not fit:
   * BN_FORMAT_ADD_OUTPUT_CHAR does memset(output, 0, output_length) on
   * overflow. Ignoring the return therefore renders an EMPTY amount on the
   * confirmation screen, and an empty string is the one rendering a user
   * cannot read as wrong -- they approve a transfer whose value was never
   * shown. A 256-bit value at 18 decimals needs ~80 characters, so this is
   * reachable with an ordinary large-amount transfer, not a corner case.
   *
   * Never leave the caller a blank amount. Say the value could not be shown,
   * so the screen is refusable rather than silently empty. */
  if (bn_format(amnt, NULL, suffix, decimals, 0, false, buf, buflen) == 0) {
    strlcpy(buf, _("AMOUNT TOO LARGE TO DISPLAY"), buflen);
    return false;
  }
  return true;
}

bool ethereumFormatNativeAmount(const bignum256* amnt, uint32_t cid, char* buf,
                                int buflen) {
  /* Stale wanchain_tx_type must never label this amount " WAN". */
  const uint32_t saved = wanchain_tx_type;
  wanchain_tx_type = 0;
  const bool ok = ethereumFormatAmount(amnt, NULL, cid, buf, buflen);
  wanchain_tx_type = saved;
  return ok;
}

static bool layoutEthereumConfirmTx(const uint8_t* to, uint32_t to_len,
                                    const uint8_t* value, uint32_t value_len,
                                    const TokenType* token, char* out_str,
                                    size_t out_str_len, bool approve,
                                    bool* contact) {
  bignum256 val;
  uint8_t pad_val[32];
  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - value_len), value, value_len);
  bn_read_be(pad_val, &val);

  /* 256-bit at 18 decimals is 60 integer digits + '.' + 18 fractional + a
   * suffix, so 32 bytes silently blanked the amount for ordinary large
   * transfers. Size it so the formatter cannot overflow at all; the guard in
   * ethereumFormatAmount() remains as the backstop. */
  char amount[96];
  if (token == NULL) {
    if (bn_is_zero(&val)) {
      strcpy(amount, _("message"));
    } else {
      if (!ethereumFormatAmount(&val, NULL, chain_id, amount, sizeof(amount)))
        return false;
    }
  } else {
    if (!ethereumFormatAmount(&val, token, chain_id, amount, sizeof(amount)))
      return false;
  }

  char addr[43] = "0x";
  if (to_len) {
    ethereum_address_checksum(to, addr + 2, false, chain_id);
  }

  bool approve_all =
      approve && value_len == 32 &&
      memcmp(value, "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0 &&
      memcmp(value + 8, "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0 &&
      memcmp(value + 16, "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0 &&
      memcmp(value + 24, "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0;

  const char* address = addr;
  if (contact && *contact) {
    char network[20];
    snprintf(network, sizeof(network), "eip155:%lu", (unsigned long)chain_id);
    *contact =
        !approve && to_len == 20 &&
        contact_book_match(network, CONTACT_BOOK_DEST_EVM_ADDRESS, to, 20);
  }
  if (contact && *contact) {
    address = contact_book_label();
  } else if (to_len && makerdao_isOasisDEXAddress(to, chain_id)) {
    address = "OasisDEX";
  }

  int cx;
  if (approve && bn_is_zero(&val) && token) {
    cx = snprintf(out_str, out_str_len, "Remove ability for %s to withdraw %s?",
                  address, token->ticker + 1);
  } else if (approve_all) {
    cx = snprintf(out_str, out_str_len,
                  "Unlock full %s balance for withdrawal by %s?",
                  token->ticker + 1, address);
  } else if (approve) {
    cx = snprintf(out_str, out_str_len, "Approve withdrawal of up to %s by %s?",
                  amount, address);
  } else {
    cx = snprintf(out_str, out_str_len, "Send %s to %s", amount,
                  to_len ? address : "new contract?");
  }

  if (out_str_len <= (size_t)cx) {
    /*error detected. Clear the buffer */
    memset(out_str, 0, out_str_len);
    return false;
  }
  return true;
}

static bool confirm_ethereum_data_hash(void) {
  uint8_t digest[32];
  char hex_digest[65];

  keccak_Final(&data_keccak_ctx, digest);
  data2hex(digest, sizeof(digest), hex_digest);
  data_hash_pending = false;

  /* ASCII hex lets an AdvancedMode user compare the exact Keccak-256 with a
   * host-side value. confirm_bytes() guarantees all 64 characters are shown
   * if a future layout/font makes them span more than one screen. */
  const bool approved = confirm_bytes(
      ButtonRequestType_ButtonRequest_ConfirmOutput, "Ethereum Data Hash",
      (const uint8_t*)hex_digest, sizeof(hex_digest) - 1);
  memzero(digest, sizeof(digest));
  memzero(hex_digest, sizeof(hex_digest));
  return approved;
}

static void formatEthereumFee(bignum256* fee, const uint8_t* gas_price,
                              const uint8_t gas_price_len) {
  uint8_t pad_val[32];

  bn_zero(fee);
  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - gas_price_len), gas_price, gas_price_len);
  bn_read_be(pad_val, fee);
}

static void formatEthereumFeeEIP1559(bignum256* fee,
                                     const uint8_t* max_fee_per_gas,
                                     const uint8_t max_fee_per_gas_len) {
  bignum256 max_fee;
  uint8_t pad_val[32];

  bn_zero(fee);

  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - max_fee_per_gas_len), max_fee_per_gas,
         max_fee_per_gas_len);
  bn_read_be(pad_val, &max_fee);

  bn_add(fee, &max_fee);
}

static bool layoutEthereumFee(const EthereumSignTx* msg, bool is_token,
                              char* out_str, size_t out_str_len) {
  bignum256 val, gas;
  /* Sized like the Send screen's amount: a value that screen showed and the
   * user approved must not be refused here for being long. */
  char gas_value[96];
  char tx_value[96];
  uint8_t pad_val[32];

  memzero(gas_value, sizeof(gas_value));
  memzero(tx_value, sizeof(tx_value));

  if (ethereum_tx_type == ETHEREUM_TX_TYPE_EIP_1559) {
    formatEthereumFeeEIP1559(&val, msg->max_fee_per_gas.bytes,
                             msg->max_fee_per_gas.size);
  } else {
    formatEthereumFee(&val, msg->gas_price.bytes, msg->gas_price.size);
  }

  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - msg->gas_limit.size), msg->gas_limit.bytes,
         msg->gas_limit.size);
  bn_read_be(pad_val, &gas);
  bn_multiply(&val, &gas, &secp256k1.prime);
  if (!ethereumFormatAmount(&gas, NULL, chain_id, gas_value, sizeof(gas_value)))
    return false;

  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - msg->value.size), msg->value.bytes, msg->value.size);
  bn_read_be(pad_val, &val);

  if (bn_is_zero(&val)) {
    strcpy(tx_value, is_token ? _("the tokens") : _("the message"));
  } else {
    if (!ethereumFormatAmount(&val, NULL, chain_id, tx_value, sizeof(tx_value)))
      return false;
  }

  if ((uint32_t)snprintf(
          out_str, out_str_len,
          _("Send %s from your wallet, paying up to %s for gas?"), tx_value,
          gas_value) >= out_str_len) {
    /*error detected.  Clear the buffer */
    memset(out_str, 0, out_str_len);
    return false;
  }
  return true;
}

/*
 * RLP fields: (legacy)
 * - nonce (0 .. 32)
 * - gas_price (0 .. 32)
 * - gas_limit (0 .. 32)
 * - to (0, 20)
 * - value (0 .. 32)
 * - data (0 ..)
 */

static bool ethereum_signing_check(const EthereumSignTx* msg) {
  if (!msg->has_gas_limit) {
    return false;
  }

  if (!(msg->has_gas_price || msg->has_max_fee_per_gas)) {
    return false;
  }

  if (msg->to.size != 20 && msg->to.size != 0) {
    /* Address has wrong length */
    return false;
  }

  // sending transaction to address 0 (contract creation) without a data field
  if (msg->to.size == 0 && (!msg->has_data_length || msg->data_length == 0)) {
    return false;
  }

  // Sanity-bound the fee field that this tx type actually uses, so the
  // on-screen fee (fee_per_gas * gas_limit) cannot overflow into the modular
  // bn_multiply and display a wrong value. EIP-1559 uses max_fee_per_gas;
  // legacy uses gas_price (which is 0 for EIP-1559 and vice versa).
  size_t fee_per_gas_size = msg->has_max_fee_per_gas ? msg->max_fee_per_gas.size
                                                     : msg->gas_price.size;
  if (fee_per_gas_size + msg->gas_limit.size > 30) {
    return false;
  }

  return true;
}

static bool ethereum_warnUnlimitedOrAbort(const EthereumSignTx* msg) {
  if (ethereum_confirmUnlimitedApproval(msg->has_chain_id ? msg->chain_id : 0,
                                        msg->data_initial_chunk.bytes + 16,
                                        msg->to.bytes)) {
    return true;
  }
  fsm_sendFailure(FailureType_Failure_ActionCancelled,
                  "Signing cancelled by user");
  ethereum_signing_abort();
  return false;
}

void ethereum_signing_init(EthereumSignTx* msg, const HDNode* node,
                           bool needs_confirm) {
  char confirm_body_message[ETHEREUM_CONFIRM_BODY_SIZE] = {0};

  ethereum_signing = true;
  data_hash_pending = false;
  memzero(&data_keccak_ctx, sizeof(data_keccak_ctx));
  sha3_256_Init(&keccak_ctx);

  memset(&msg_tx_request, 0, sizeof(EthereumTxRequest));
  /* set fields to 0, to avoid conditions later */
  if (!msg->has_value) msg->value.size = 0;
  if (!msg->has_data_initial_chunk) msg->data_initial_chunk.size = 0;
  if (!msg->has_to) msg->to.size = 0;
  if (!msg->has_nonce) msg->nonce.size = 0;

  // RLP treats an all-zero integer as zero regardless of its wire length.
  // Canonicalize before contract and generic classifiers inspect this value.
  if (msg->value.size > 0) {
    bool all_zero = true;
    for (size_t i = 0; i < msg->value.size; ++i) {
      all_zero &= msg->value.bytes[i] == 0;
    }
    if (all_zero) msg->value.size = 0;
  }

  /* eip-155 chain id
   *
   * An absent chain_id is not "some other chain", it is no chain. The bounds
   * check below used to live inside `if (msg->has_chain_id)`, so a host that
   * simply omitted the field landed on chain_id == 0 — the exact value the
   * `< 1` reject exists to forbid — and got there without tripping it.
   *
   * Two things then go wrong at once, and the second is what makes it a
   * signing bug rather than a compatibility wart:
   *
   *   - send_signature() appends the EIP-155 fields to the keccak preimage
   *     only `if (chain_id)`, and falls back to signature_v = v + 27. The
   *     device emits a pre-EIP-155 signature: not a payment on one chain, but
   *     a bearer authorization valid on every EVM chain where this address is
   *     funded at this nonce.
   *   - ethereumFormatAmount() switches on the chain id to pick a ticker.
   *     cid 0 matches no case, so suffix stays NULL and bn_format() renders a
   *     bare number. No screen in the flow names a network, so the user
   *     approves "Send 0.05 to 0xABC" and cannot see either omission.
   *
   * So reject it for every transaction type, the way the EIP-1559 path below
   * already does for itself. Every chain this firmware supports has a chain
   * id >= 1; a host omitting the field is malformed, not legacy.
   */
  chain_id = msg->has_chain_id ? msg->chain_id : 0;
  if (!ethereum_chainIdIsValid(msg)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Chain Id out of bounds"));
    ethereum_signing_abort();
    return;
  }

  /* Wanchain txtype */
  if (msg->has_tx_type) {
    if (msg->tx_type == 1 || msg->tx_type == 6) {
      wanchain_tx_type = msg->tx_type;
    } else {
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Txtype out of bounds"));
      ethereum_signing_abort();
      return;
    }
  } else {
    wanchain_tx_type = 0;
  }

  /* Ethereum tx type */
  if (msg->has_type) {
    if (msg->type == 0 || msg->type == 2) {
      ethereum_tx_type = msg->type;
    } else {
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Ethereum tx type out of bounds"));
      ethereum_signing_abort();
      return;
    }
  } else {
    ethereum_tx_type = ETHEREUM_TX_TYPE_LEGACY;
  }

  /* The typed prefix (0x02) and access list are emitted based on
   * ethereum_tx_type, while the fee fields are selected by has_max_fee_per_gas.
   * If those two disagree, Stage 1 (rlp_length) and Stage 2 (hashed bytes)
   * describe different field lists and the signature recovers to a wrong
   * address. Enforce a consistent shape up front. */
  if (ethereum_tx_type == ETHEREUM_TX_TYPE_EIP_1559) {
    if (chain_id == 0) {
      /* chain_id is the mandatory first RLP field of an EIP-1559 tx; absent
       * chain_id is counted (1 byte) in Stage 1 but hash_rlp_number(0) hashes
       * nothing in Stage 2. */
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("EIP-1559 transactions require chain_id"));
      ethereum_signing_abort();
      return;
    }
    if (!msg->has_max_fee_per_gas) {
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("EIP-1559 transactions require max_fee_per_gas"));
      ethereum_signing_abort();
      return;
    }
  } else if (msg->has_max_fee_per_gas) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("max_fee_per_gas requires an EIP-1559 (type 2) tx"));
    ethereum_signing_abort();
    return;
  }

  if (ethereum_tx_type == ETHEREUM_TX_TYPE_LEGACY && !msg->has_gas_price) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Legacy transactions require gas_price"));
    ethereum_signing_abort();
    return;
  }

  if (msg->has_data_length && msg->data_length > 0) {
    if (!msg->has_data_initial_chunk || msg->data_initial_chunk.size == 0) {
      fsm_sendFailure(FailureType_Failure_Other,
                      _("Data length provided, but no initial chunk"));
      ethereum_signing_abort();
      return;
    }
    /* Our encoding only supports transactions up to 2^24 bytes.  To
     * prevent exceeding the limit we use a stricter limit on data length.
     */
    if (msg->data_length > 16000000) {
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Data length exceeds limit"));
      ethereum_signing_abort();
      return;
    }
    data_total = msg->data_length;
  } else {
    data_total = 0;
  }
  if (msg->data_initial_chunk.size > data_total) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid size of initial chunk"));
    ethereum_signing_abort();
    return;
  }

  const TokenType* token = NULL;

  // safety checks
  if (!ethereum_signing_check(msg)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Safety check failed"));
    ethereum_signing_abort();
    return;
  }

  // Keep the selector and both ABI words available to the allowance policy.
  // Otherwise a host could split an approval prefix across streamed chunks.
  const size_t selector_bytes =
      msg->data_initial_chunk.size < 4 ? msg->data_initial_chunk.size : 4;
  if (msg->has_to && msg->to.size == 20 && data_total >= 68 &&
      msg->data_initial_chunk.size < 68 &&
      ethereum_isAllowanceSelector(msg->data_initial_chunk.bytes,
                                   selector_bytes)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Approval requires at least 68 initial bytes"));
    ethereum_signing_abort();
    return;
  }

  // Match the selector alone. Pre-0.8 Solidity masks the spender word's high
  // bytes, so a dirty spender word still grants the allowance on chain.
  bool unlimited_deferred = false;
  if (msg->has_to && msg->to.size == 20 && data_total >= 68 &&
      ethereum_isAllowanceSelector(msg->data_initial_chunk.bytes, 4)) {
    if (!ethereum_allowanceIsWellFormed(msg)) {
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Malformed ERC20 approval"));
      ethereum_signing_abort();
      return;
    }
    // Native value cannot exempt a payable token from this warning. It comes
    // before any contract, metadata or generic screen, so none can mask it,
    // except a certified review (SRS-7.16 R-7.4): its summary states the
    // amount as UNLIMITED <symbol>, so the warning waits for that review and
    // is shown only if the review does not run.
    if (ethereum_allowanceIsUnlimited(msg)) {
      unlimited_deferred =
          signed_metadata_certified_states_allowance(msg, chain_id);
      if (!unlimited_deferred && !ethereum_warnUnlimitedOrAbort(msg)) return;
    }
  }

  /* A deposit its pinned THORChain/Maya router can only revert is refused
   * with the reason, before any screen, rather than signed. */
  const char* thor_refusal = thor_depositRefusal(msg);
  if (thor_refusal) {
    fsm_sendFailure(FailureType_Failure_Other, thor_refusal);
    ethereum_signing_abort();
    return;
  }

  bool data_needs_confirm = true;
  if (ethereum_contractHandled(data_total, msg, node)) {
    if (!ethereum_contractConfirmed(data_total, msg, node)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Signing cancelled by user");
      ethereum_signing_abort();
      return;
    }
    needs_confirm = false;
    data_needs_confirm = false;
  }

  /* D-007: a KeepKey-certified ERC-7730 review of this calldata replaces the
   * raw-data review. This pass re-hashes every byte against the reviewed
   * digest and send_signature() refuses unless it matched; the amount and
   * fee screens stay. */
  const Erc7730Workflow* certified = erc7730_workflow_state();
  if (data_needs_confirm && certified->signing_pass && !certified->typed_data &&
      certified->phase == ERC7730_WORKFLOW_CALLDATA &&
      erc7730_workflow_certified(certified)) {
    data_needs_confirm = false;
  }

  /* SRS R-1.4: a certified claim is honoured completely or refused, never
   * downgraded. Checked before any screen, so a failed claim never shows
   * "Verified by KeepKey". */
  if (data_needs_confirm && data_total > 0 &&
      signed_metadata_certified_claimed() &&
      !(signed_metadata_available() && signed_metadata_matches_tx(msg) &&
        signed_metadata_may_suppress(chain_id))) {
    /* A certified Uniswap swap past the first chunk: nothing is shown from
     * a prefix. Its review follows the fee screen, once every byte is in.
     * Pending implies a KeepKey-certified entry for this chain. */
    if (!signed_metadata_ur_pending()) {
      fsm_sendFailure(FailureType_Failure_Other,
                      _("Certified description invalid or not for this tx"));
      ethereum_signing_abort();  // clears metadata
      return;
    }
    needs_confirm = false;
    data_needs_confirm = false;
  }

  // Signed metadata clear signing (backwards compatible).
  // Only fires if host sent EthereumTxMetadata before this EthereumSignTx.
  if (data_needs_confirm && data_total > 0 && signed_metadata_available()) {
    if (signed_metadata_matches_tx(msg)) {
      if (signed_metadata_confirm()) {
        /* Suppression is the POSITIVE arm. A v2 schema cannot bind
         * msg->value, so payable calls still show amount/recipient. */
        if (signed_metadata_may_suppress(chain_id)) {
          needs_confirm = signed_metadata_schema_moves_value();
          data_needs_confirm = false;
          unlimited_deferred = false;  // the certified review stated it
        } else {
          /* Runtime signer: annotation only; the raw review stays. */
          needs_confirm = true;
          data_needs_confirm = true;
        }
      } else {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Signing cancelled by user");
        ethereum_signing_abort();  // clears metadata
        return;
      }
    }
  }
  if (unlimited_deferred && !ethereum_warnUnlimitedOrAbort(msg)) return;
  // Keep metadata only when its decoded screens were approved, so their
  // attestation remains bound to the signature. Otherwise prevent stale reuse
  // when contractHandled / ERC-20 paths bypassed metadata review.
  if (!signed_metadata_ur_pending() && !signed_metadata_relied()) {
    signed_metadata_clear();
  }

  // detect ERC-20 token
  if (data_total == 68 && ethereum_isStandardERC20Transfer(msg)) {
    token = tokenByChainAddress(chain_id, msg->to.bytes);
  }

  bool is_approve = false;
  if (data_total == 68 && ethereum_isStandardERC20Approve(msg)) {
    token = tokenByChainAddress(chain_id, msg->to.bytes);
    is_approve = true;
  }

  /* A certified contact labels only a plain recipient (a native send with no
   * calldata, or a known-token transfer) and never sits beside a contract
   * description: none may be loaded, signed metadata or ERC-7730. Nor on a
   * Wanchain-type request: its chain id is not an EIP-155 network the contact
   * was certified for. */
  bool contact = !is_approve && wanchain_tx_type == 0 &&
                 !signed_metadata_available() &&
                 erc7730_workflow_state()->phase == ERC7730_WORKFLOW_IDLE &&
                 (token == NULL ? data_total == 0 : token != UnknownToken);
  const uint8_t* recipient = NULL;
  if (needs_confirm) {
    if (token == UnknownToken) {
      if (!ethereumFormatUnknownTokenReview(msg, confirm_body_message,
                                            sizeof(confirm_body_message))) {
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Ethereum amount too large"));
        ethereum_signing_abort();
        return;
      }
    } else if (token != NULL) {
      recipient = msg->data_initial_chunk.bytes + 16;
      if (!layoutEthereumConfirmTx(
              recipient, 20, msg->data_initial_chunk.bytes + 36, 32, token,
              confirm_body_message, sizeof(confirm_body_message),
              /*approve=*/is_approve, &contact)) {
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Ethereum amount too large"));
        ethereum_signing_abort();
        return;
      }
    } else {
      recipient = msg->to.bytes;
      if (!layoutEthereumConfirmTx(recipient, msg->to.size, msg->value.bytes,
                                   msg->value.size, NULL, confirm_body_message,
                                   sizeof(confirm_body_message),
                                   /*approve=*/false, &contact)) {
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Ethereum amount too large"));
        ethereum_signing_abort();
        return;
      }
    }
    bool is_transfer = msg->address_type == OutputAddressType_TRANSFER;
    const char* title;
    ButtonRequestType BRT;
    if (is_approve) {
      title = "Approve";
      BRT = ButtonRequestType_ButtonRequest_ConfirmOutput;
    } else if (is_transfer) {
      title = "Transfer";
      BRT = ButtonRequestType_ButtonRequest_ConfirmTransferToAccount;
    } else {
      title = "Send";
      BRT = ButtonRequestType_ButtonRequest_ConfirmOutput;
    }
    if (!confirm(BRT, title, "%s", confirm_body_message)) {
      contact_book_clear();
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Signing cancelled by user");
      ethereum_signing_abort();
      return;
    }
    /* The label replaced the address on the screen above: show it too. */
    if (contact && recipient) {
      char raw[43] = "0x";
      ethereum_address_checksum(recipient, raw + 2, false, chain_id);
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Contact Address", "%s", raw)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Signing cancelled by user");
        ethereum_signing_abort();
        return;
      }
    }
  }
  /* A proof labels exactly one signing request. */
  contact_book_clear();

  memset(confirm_body_message, 0, sizeof(confirm_body_message));
  // A contract that is not in the token table yields the UnknownToken
  // sentinel, which is NOT NULL, so the original `token == NULL` guard let
  // ERC-20-shaped calldata to an unrecognized contract skip this block
  // entirely. Exact raw units do not establish the contract semantics, so
  // unknown tokens still require the raw-data disclosure and confirmation
  // gate used by other unrecognized contract calls.
  if ((token == NULL || token == UnknownToken) && data_total > 0 &&
      data_needs_confirm) {
    // KeepKey custom: gate arbitrary ETH contract-data signing on AdvancedMode.
    // The prior code was a (void)review() warning whose return value was
    // discarded, so a user who cancelled the warning still fell through to
    // the confirm() dialog and signed. This now blocks, mirroring
    // fsm_msgTronSignTx / fsm_msgSolanaSignMessage / fsm_msgTonSignMessage.
    // See GH #433.
    if (!storage_isPolicyEnabled("AdvancedMode")) {
      (void)review(
          ButtonRequestType_ButtonRequest_Other, "Blocked",
          "Signing of arbitrary ETH contract data requires AdvancedMode. "
          "Enable 'AdvancedMode' policy in device settings.");
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Arbitrary contract data signing disabled by policy"));
      ethereum_signing_abort();
      return;
    }

    /* A prefix preview cannot commit to executable bytes in later chunks.
     * Collect the complete calldata and approve its Keccak-256 only after the
     * last byte has arrived. */
    sha3_256_Init(&data_keccak_ctx);
    sha3_Update(&data_keccak_ctx, msg->data_initial_chunk.bytes,
                msg->data_initial_chunk.size);
    data_hash_pending = true;
  }

  if (is_approve) {
    token = NULL;
  }

  memset(confirm_body_message, 0, sizeof(confirm_body_message));
  if (!layoutEthereumFee(msg, token != NULL, confirm_body_message,
                         sizeof(confirm_body_message))) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Ethereum fee too large"));
    ethereum_signing_abort();
    return;
  }
  char transaction_title[24];
  ethereum_transactionTitle(msg, transaction_title, sizeof(transaction_title));
  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, transaction_title, "%s",
               confirm_body_message)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Signing cancelled by user");
    ethereum_signing_abort();
    return;
  }

  /* Stage 1: Calculate total RLP length */
  uint32_t rlp_length = 0;
  layoutProgress(_("Signing"), 0);

  if (ethereum_tx_type == ETHEREUM_TX_TYPE_EIP_1559) {
    rlp_length += rlp_calculate_number_length(chain_id);
  }

  rlp_length +=
      rlp_calculate_length_stripped(msg->nonce.bytes, msg->nonce.size);
  if (msg->has_max_fee_per_gas) {
    rlp_length +=
        rlp_calculate_length_stripped(msg->max_priority_fee_per_gas.bytes,
                                      msg->max_priority_fee_per_gas.size);
    rlp_length += rlp_calculate_length_stripped(msg->max_fee_per_gas.bytes,
                                                msg->max_fee_per_gas.size);
  } else {
    rlp_length += rlp_calculate_length_stripped(msg->gas_price.bytes,
                                                msg->gas_price.size);
  }

  rlp_length +=
      rlp_calculate_length_stripped(msg->gas_limit.bytes, msg->gas_limit.size);
  rlp_length += rlp_calculate_length(msg->to.size, msg->to.bytes[0]);
  rlp_length +=
      rlp_calculate_length_stripped(msg->value.bytes, msg->value.size);
  rlp_length +=
      rlp_calculate_length(data_total, msg->data_initial_chunk.bytes[0]);

  if (ethereum_tx_type == ETHEREUM_TX_TYPE_EIP_1559) {
    // access list size
    rlp_length +=
        1;  // c0, keepkey does not support >0 length access list at this time
  }

  if (wanchain_tx_type) {
    rlp_length += rlp_calculate_number_length(wanchain_tx_type);
  }

  if (ethereum_tx_type == ETHEREUM_TX_TYPE_LEGACY) {
    // legacy EIP-155 replay protection
    if (chain_id) {
      rlp_length += rlp_calculate_number_length(chain_id);
      rlp_length += rlp_calculate_length(0, 0);
      rlp_length += rlp_calculate_length(0, 0);
    }
  }

  // Start the hash:
  // keccak256(0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas,
  // max_fee_per_gas,
  //           gas_limit, destination, amount, data, access_list]))

  // tx type should never be greater than one byte in length
  // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2718.md#transactiontype-only-goes-up-to-0x7f
  if (ethereum_tx_type == ETHEREUM_TX_TYPE_EIP_1559) {
    uint8_t datbuf[1] = {0x02};
    hash_data(datbuf, sizeof(datbuf));
  }

  layoutProgress(_("Signing"), 100);
  /* Stage 2: Store header fields */
  hash_rlp_list_length(rlp_length);

  if (wanchain_tx_type) {
    hash_rlp_number(wanchain_tx_type);
  }

  if (ethereum_tx_type == ETHEREUM_TX_TYPE_EIP_1559) {
    hash_rlp_number(chain_id);
  }

  hash_rlp_bytes_stripped(msg->nonce.bytes, msg->nonce.size);

  if (msg->has_max_fee_per_gas) {
    /* max_priority_fee_per_gas is a mandatory EIP-1559 field; when absent it
     * encodes as the empty integer (0x80). Stage 1 always counts it
     * (unconditionally, above), so Stage 2 must always hash it too -- guarding
     * on has_max_priority_fee_per_gas here would under-hash and leave the list
     * header over-declared (the same wrong-signer class this commit fixes).
     * .size is 0 when unset, which hash_rlp_bytes_stripped emits as 0x80. */
    hash_rlp_bytes_stripped(msg->max_priority_fee_per_gas.bytes,
                            msg->max_priority_fee_per_gas.size);
    hash_rlp_bytes_stripped(msg->max_fee_per_gas.bytes,
                            msg->max_fee_per_gas.size);
  } else {
    hash_rlp_bytes_stripped(msg->gas_price.bytes, msg->gas_price.size);
  }

  hash_rlp_bytes_stripped(msg->gas_limit.bytes, msg->gas_limit.size);
  hash_rlp_field(msg->to.bytes, msg->to.size); /* address: no strip */
  hash_rlp_bytes_stripped(msg->value.bytes, msg->value.size);
  hash_rlp_length(data_total, msg->data_initial_chunk.bytes[0]);
  hash_data(msg->data_initial_chunk.bytes, msg->data_initial_chunk.size);
  data_left = data_total - msg->data_initial_chunk.size;

  Erc7730Workflow* erc7730 = erc7730_workflow_state();
  if (erc7730->phase == ERC7730_WORKFLOW_CALLDATA && data_left == 0 &&
      erc7730_workflow_calldata_finish(erc7730) != ERC7730_ABI_OK) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("ERC-7730 calldata does not match definition"));
    ethereum_signing_abort();
    return;
  }

  if (data_left == 0 && data_hash_pending && !confirm_ethereum_data_hash()) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Signing cancelled by user");
    ethereum_signing_abort();
    return;
  }

  memcpy(privkey, node->private_key, 32);

  if (data_left > 0) {
    send_request_chunk();
  } else {
    finalize_eip1559_and_send_signature();
  }
}

void ethereum_signing_txack(EthereumTxAck* tx) {
  if (!ethereum_signing) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Not in Ethereum signing mode"));
    layoutHome();
    return;
  }

  if (tx->data_chunk.size > data_left) {
    fsm_sendFailure(FailureType_Failure_Other, _("Too much data"));
    ethereum_signing_abort();
    return;
  }

  if (data_left > 0 && (!tx->has_data_chunk || tx->data_chunk.size == 0)) {
    fsm_sendFailure(FailureType_Failure_Other, _("Empty data chunk received"));
    ethereum_signing_abort();
    return;
  }

  if (data_hash_pending) {
    sha3_Update(&data_keccak_ctx, tx->data_chunk.bytes, tx->data_chunk.size);
  }
  Erc7730Workflow* erc7730 = erc7730_workflow_state();
  if (erc7730->phase == ERC7730_WORKFLOW_CALLDATA &&
      erc7730_workflow_calldata_feed(erc7730, tx->data_chunk.bytes,
                                     tx->data_chunk.size) != ERC7730_ABI_OK) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("ERC-7730 calldata does not match definition"));
    ethereum_signing_abort();
    return;
  }
  hash_data(tx->data_chunk.bytes, tx->data_chunk.size);

  data_left -= tx->data_chunk.size;

  /* A certified Uniswap call held since init: decoded at its last byte and
   * reviewed then. Refused, never downgraded (SRS R-1.4), as at init. */
  if (signed_metadata_ur_pending()) {
    if (!signed_metadata_ur_feed(tx->data_chunk.bytes, tx->data_chunk.size)) {
      fsm_sendFailure(FailureType_Failure_Other,
                      _("Certified description invalid or not for this tx"));
      ethereum_signing_abort();
      return;
    }
    if (data_left == 0 && !signed_metadata_confirm()) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Signing cancelled by user");
      ethereum_signing_abort();
      return;
    }
  }

  if (erc7730->phase == ERC7730_WORKFLOW_CALLDATA && data_left == 0 &&
      erc7730_workflow_calldata_finish(erc7730) != ERC7730_ABI_OK) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("ERC-7730 calldata does not match definition"));
    ethereum_signing_abort();
    return;
  }

  if (data_left == 0 && data_hash_pending && !confirm_ethereum_data_hash()) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Signing cancelled by user");
    ethereum_signing_abort();
    return;
  }

  if (data_left > 0) {
    send_request_chunk();
  } else {
    finalize_eip1559_and_send_signature();
  }
}

void ethereum_signing_abort(void) {
  if (ethereum_signing) {
    memzero(privkey, sizeof(privkey));
    data_hash_pending = false;
    memzero(&data_keccak_ctx, sizeof(data_keccak_ctx));
    signed_metadata_clear();
    contact_book_clear();
    layoutHome();
    ethereum_signing = false;
  }
  if (erc7730_workflow_state()->phase != ERC7730_WORKFLOW_IDLE)
    erc7730_workflow_abort(erc7730_workflow_state());
}

/* Whether a signing flow is mid-flight. The clearsign metadata handlers
 * refuse to accept metadata once signing has started. */
bool ethereum_signing_isInProgress(void) { return ethereum_signing; }

static void ethereum_message_hash(const uint8_t* message, size_t message_len,
                                  uint8_t hash[32]) {
  struct SHA3_CTX ctx;
  uint8_t c;

  sha3_256_Init(&ctx);
  sha3_Update(&ctx, (const uint8_t *)"\x19" "Ethereum Signed Message:\n", 26);
  if (message_len >= 1000000000) {
    c = '0' + message_len / 1000000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 100000000) {
    c = '0' + message_len / 100000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 10000000) {
    c = '0' + message_len / 10000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 1000000) {
    c = '0' + message_len / 1000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 100000) {
    c = '0' + message_len / 100000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 10000) {
    c = '0' + message_len / 10000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 1000) {
    c = '0' + message_len / 1000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 100) {
    c = '0' + message_len / 100 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 10) {
    c = '0' + message_len / 10 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  c = '0' + message_len % 10;
  sha3_Update(&ctx, &c, 1);
  sha3_Update(&ctx, message, message_len);
  keccak_Final(&ctx, hash);
}

void ethereum_message_sign(const EthereumSignMessage* msg, const HDNode* node,
                           EthereumMessageSignature* resp) {
  uint8_t hash[32];

  if (!hdnode_get_ethereum_pubkeyhash(node, resp->address.bytes)) {
    return;
  }
  resp->has_address = true;
  resp->address.size = 20;

  ethereum_message_hash(msg->message.bytes, msg->message.size, hash);

  uint8_t v;
  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash,
                        resp->signature.bytes, &v, ethereum_is_canonic) != 0) {
    fsm_sendFailure(FailureType_Failure_Other, _("Signing failed"));
    return;
  }

  resp->has_signature = true;
  resp->signature.bytes[64] = 27 + v;
  resp->signature.size = 65;
  msg_write(MessageType_MessageType_EthereumMessageSignature, resp);
}

int ethereum_message_verify(const EthereumVerifyMessage* msg) {
  if (msg->signature.size != 65 || msg->address.size != 20) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Malformed data"));
    return 1;
  }

  uint8_t pubkey[65];
  uint8_t hash[32];

  ethereum_message_hash(msg->message.bytes, msg->message.size, hash);

  /* v should be 27, 28 but some implementations use 0,1.  We are
   * compatible with both.
   */
  uint8_t v = msg->signature.bytes[64];
  if (v >= 27) {
    v -= 27;
  }
  if (v >= 2 || ecdsa_recover_pub_from_sig(
                    &secp256k1, pubkey, msg->signature.bytes, hash, v) != 0) {
    return 2;
  }

  struct SHA3_CTX ctx;
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, pubkey + 1, 64);
  keccak_Final(&ctx, hash);

  /* result are the least significant 160 bits */
  if (memcmp(msg->address.bytes, hash + 12, 20) != 0) {
    return 2;
  }
  return 0;
}

//
/*
 * EIP-712 hashes might have no message_hash if primaryType="EIP712Domain".
 * In this case, set has_message_hash=false.
 */
static void ethereum_typed_hash(const uint8_t domain_separator_hash[32],
                                const uint8_t message_hash[32],
                                bool has_message_hash, uint8_t hash[32]) {
  struct SHA3_CTX ctx = {0};
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, (const uint8_t*)"\x19\x01", 2);
  sha3_Update(&ctx, domain_separator_hash, 32);
  if (has_message_hash) {
    sha3_Update(&ctx, message_hash, 32);
  }
  keccak_Final(&ctx, hash);
}

static int eip712_sign(const uint8_t* ds_hash, const uint8_t* msg_hash,
                       bool has_msg_hash, const HDNode* node, uint8_t* v,
                       uint8_t* sig) {
  uint8_t hash[32] = {0};

  ethereum_typed_hash(ds_hash, msg_hash, has_msg_hash, hash);

  return ecdsa_sign_digest(&secp256k1, node->private_key, hash, sig, v,
                           ethereum_is_canonic);
}

void ethereum_typed_hash_sign(const EthereumSignTypedHash* msg,
                              const HDNode* node,
                              EthereumTypedDataSignature* resp) {
  uint8_t v = 0;
  if (0 != eip712_sign(msg->domain_separator_hash.bytes,
                       msg->message_hash.bytes, msg->has_message_hash, node, &v,
                       resp->signature.bytes)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("EIP-712 hash signing failed"));
    return;
  }

  resp->signature.bytes[64] = 27 + v;
  resp->signature.size = 65;
  msg_write(MessageType_MessageType_EthereumTypedDataSignature, resp);
}

void failMessage(int err);

const char* failMsgReturn[LAST_ERROR - 2] = {
    "EIP-712 general error",  //  3
    "EIP-712 user defined type name too long",
    "EIP-712 too many user defined types",
    "EIP-712 user defined type array name error",
    "EIP-712 invalid address string",
    "EIP-712 bytesN string overflow",
    "EIP-712 bytesN size error",
    "EIP-712 INT and UINT array parsing not implemented",
    "EIP-712 bytesN array parsing not implemented",
    "EIP-712 boolean array parsing not implemented",
    "EIP-712 not enough memory to parse message",  // 13
    "EIP-712 primaryType name error",
    "EIP-712 primaryType value error",
    "EIP-712 types property error",
    "EIP-712 typeS (typestring) property error",
    "EIP-712 domain property name error",
    "EIP-712 domain seperator hash must be calculated first",
    "EIP-712 message property name error",
    "EIP-712 primary type object error",
    "EIP-712 typeS not found in eip712types",
    "EIP-712 typeS name missing",  // 23
    "EIP-712 unused error 24",
    "EIP-712 pairs are NULL",
    "EIP-712 json pair type is not JSON_TEXT",
    "EIP-712 pair does not have a sibling",
    "EIP-712 typeType not encodable, possibly NULL",
    "EIP-712 pair value is NULL",
    "EIP-712 pair name is NULL",
    "EIP-712 typeType has no name in parseVals",
    "EIP-712 address string is NULL",
    "EIP-712 no value for type during walkVals",  // 33
};

void failMessage(int err) {
  if (USER_CANCELLED == err) {
    /* Not a parse failure: a typed-data review screen ended without a
       completed button hold, which is what confirm_helper() reports when the
       host sends Cancel or Initialize. Report it as a cancellation so the host
       does not read a refusal as a malformed message. USER_CANCELLED is above
       LAST_ERROR and has no failMsgReturn[] slot, so this branch must come
       first. */
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("EIP-712 cancelled"));
    return;
  }
  if (err < GENERAL_ERROR || err > LAST_ERROR) {
    // unknown error number
    fsm_sendFailure(FailureType_Failure_Other, _("EIP-712 unknown failure"));
  } else {
    fsm_sendFailure(FailureType_Failure_Other, _(failMsgReturn[err - 3]));
  }
  return;
}

void e712_types_values(Ethereum712TypesValues* msg,
                       EthereumTypedDataSignature* resp, const HDNode* node) {
  int errRet = SUCCESS;
  json_t memTypes[JSON_OBJ_POOL_SIZE] = {0};
  json_t memVals[JSON_OBJ_POOL_SIZE] = {0};
  json_t memPType[4] = {0};
  json_t const* jsonT;
  json_t const* jsonV;
  json_t const* jsonPT;
  char* typesJsonStr;
  char* primaryTypeJsonStr;
  char* valuesJsonStr;
  json_t const* obTest;
  static uint8_t domainSeparatorHash[32] = {0};
  // cppcheck-suppress variableScope
  static uint8_t messageHash[32] = {0};
  static bool have_ds = false;

  typesJsonStr = msg->eip712types;
  primaryTypeJsonStr = msg->eip712primetype;
  valuesJsonStr = msg->eip712data;

  jsonT =
      json_create(typesJsonStr, memTypes, sizeof memTypes / sizeof *memTypes);
  jsonPT = json_create(primaryTypeJsonStr, memPType,
                       sizeof memPType / sizeof *memPType);
  jsonV = json_create(valuesJsonStr, memVals, sizeof memVals / sizeof *memVals);

  if (!jsonT) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("EIP-712 type property data error"));
    return;
  }
  if (!jsonPT) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("EIP-712 primaryType property data error"));
    return;
  }
  if (!jsonV) {
    fsm_sendFailure(FailureType_Failure_Other, _("EIP-712 values data error"));
    return;
  }

  if (msg->eip712typevals == 1) {
    // Compute domain seperator hash
    have_ds = false;
    memzero(domainSeparatorHash, 32);
    if ((int)SUCCESS != (errRet = encode(jsonT, jsonV, "EIP712Domain",
                                         resp->domain_separator_hash.bytes))) {
      failMessage(errRet);
      return;
    }
    have_ds = true;
    memcpy(domainSeparatorHash, resp->domain_separator_hash.bytes, 32);
    resp->has_domain_separator_hash = true;
    resp->domain_separator_hash.size = 32;
    resp->has_msg_hash = false;

  } else {
    if (!have_ds) {
      failMessage(MSG_NO_DS);
      return;
    }
    if (NULL == (obTest = json_getProperty(jsonPT, "primaryType"))) {
      failMessage(JSON_PTYPENAMEERR);
      return;
    }
    const char* primeType;
    if (0 == (primeType = json_getValue(obTest))) {
      failMessage(JSON_PTYPEVALERR);
      return;
    }
    if (0 != strncmp(primeType, "EIP712Domain",
                     strlen(primeType))) {  // if primaryType is "EIP712Domain",
                                            // message hash is NULL
      errRet = encode(jsonT, jsonV, primeType, resp->message_hash.bytes);
      if (!(SUCCESS == errRet || NULL_MSG_HASH == errRet)) {
        failMessage(errRet);
        return;
      }
    } else {
      errRet = NULL_MSG_HASH;
    }

    if (NULL_MSG_HASH == errRet) {
      resp->has_message_hash = false;
      resp->has_msg_hash = false;
    } else {
      memcpy(messageHash, resp->message_hash.bytes, 32);
      resp->has_message_hash = true;
      resp->message_hash.size = 32;
      resp->has_msg_hash = true;
    }
    memcpy(resp->domain_separator_hash.bytes, domainSeparatorHash, 32);
    resp->has_domain_separator_hash = true;
    resp->domain_separator_hash.size = 32;

    // Every screen shown while parsing the typed data is a review(), which
    // cannot express refusal. Take one real confirmation before producing a
    // signature so a host cannot obtain one without a button press.
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Sign Typed Data",
                 "Sign with address %s?", resp->address)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Signing cancelled by user");
      memzero(domainSeparatorHash, 32);
      memzero(messageHash, 32);
      have_ds = false;
      return;
    }

    uint8_t v = 0;
    if (0 != eip712_sign(domainSeparatorHash, messageHash, resp->has_msg_hash,
                         node, &v, resp->signature.bytes)) {
      fsm_sendFailure(FailureType_Failure_Other,
                      _("EIP-712 typed hash signing failed"));
      return;
    }

    resp->signature.bytes[64] = 27 + v;
    resp->signature.size = 65;

    memzero(domainSeparatorHash, 32);
    memzero(messageHash, 32);
    have_ds = false;
  }

  msg_write(MessageType_MessageType_EthereumTypedDataSignature, resp);
}

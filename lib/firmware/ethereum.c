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
#include "keepkey/firmware/ethereum_contracts/makerdao.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/thorchain.h"
#include "keepkey/firmware/tiny-json.h"
#include "keepkey/firmware/transaction.h"
#include "hwcrypto/crypto/address.h"
#include "hwcrypto/crypto/ecdsa.h"
#include "hwcrypto/crypto/memzero.h"
#include "hwcrypto/crypto/secp256k1.h"
#include "hwcrypto/crypto/sha3.h"

#include <stdio.h>

#define _(X) (X)

#define MAX_CHAIN_ID 2147483630

#define ETHEREUM_TX_TYPE_LEGACY 0UL
#define ETHEREUM_TX_TYPE_EIP_2930 1UL
#define ETHEREUM_TX_TYPE_EIP_1559 2UL

static bool ethereum_signing = false;
static uint32_t data_total, data_left;
static EthereumTxRequest msg_tx_request;
static CONFIDENTIAL uint8_t privkey[32];
static uint32_t chain_id;
static uint32_t wanchain_tx_type;  // Wanchain only
static uint32_t ethereum_tx_type;  // Ethereum tx type (0=Legacy, 1=EIP-2930, 2=EIP-1559)
struct SHA3_CTX keccak_ctx;

bool ethereum_isStandardERC20Transfer(const EthereumSignTx *msg) {
  if (msg->has_to && msg->to.size == 20 && msg->value.size == 0 &&
      msg->data_initial_chunk.size == 68 &&
      memcmp(msg->data_initial_chunk.bytes,
             "\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
             16) == 0) {
    return true;
  }
  return false;
}

bool ethereum_isStandardERC20Approve(const EthereumSignTx *msg) {
  if (msg->has_to && msg->to.size == 20 && msg->value.size == 0 &&
      msg->data_initial_chunk.size == 68 &&
      memcmp(msg->data_initial_chunk.bytes,
             "\x09\x5e\xa7\xb3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
             16) == 0) {
    return true;
  }
  return false;
}

bool ethereum_getStandardERC20Recipient(const EthereumSignTx *msg,
                                        char *address, size_t len) {
  if (len < 2 * 20 + 1) return false;

  data2hex(msg->data_initial_chunk.bytes + 16, 20, address);
  return true;
}

bool ethereum_getStandardERC20Coin(const EthereumSignTx *msg, CoinType *coin) {
  const CoinType *found =
      coinByChainAddress(msg->has_chain_id ? msg->chain_id : 1, msg->to.bytes);
  if (found) {
    memcpy(coin, found, sizeof(*coin));
    return true;
  }

  const TokenType *token =
      tokenByChainAddress(msg->has_chain_id ? msg->chain_id : 1, msg->to.bytes);
  if (token == UnknownToken) return false;

  coinFromToken(coin, token);
  return true;
}

void bn_from_bytes(const uint8_t *value, size_t value_len, bignum256 *val) {
  uint8_t pad_val[32];
  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - value_len), value, value_len);
  bn_read_be(pad_val, val);
  memzero(pad_val, sizeof(pad_val));
}

static inline void hash_data(const uint8_t *buf, size_t size) {
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
static void hash_rlp_field(const uint8_t *buf, size_t size) {
  hash_rlp_length(size, buf[0]);
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
  data[3] = (number)&0xff;
  int offset = 0;
  while (!data[offset]) {
    offset++;
  }
  hash_rlp_field(data + offset, 4 - offset);
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
/* Format a 256 bit number (amount in wei) into a human readable format
 * using standard ethereum units.
 * The buffer must be at least 25 bytes.
 */
void ethereumFormatAmount(const bignum256 *amnt, const TokenType *token,
                          uint32_t cid, char *buf, int buflen) {
  bignum256 bn1e9;
  bn_read_uint32(1000000000, &bn1e9);
  const char *suffix = NULL;
  int decimals = 18;
  if (token == UnknownToken) {
    strlcpy(buf, "Unknown token value", buflen);
    return;
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
          suffix = " OP";
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
      }
    }
  }
  bn_format(amnt, NULL, suffix, decimals, 0, false, buf, buflen);
}

static void layoutEthereumConfirmTx(const uint8_t *to, uint32_t to_len,
                                    const uint8_t *value, uint32_t value_len,
                                    const TokenType *token, char *out_str,
                                    size_t out_str_len, bool approve) {
  bignum256 val;
  uint8_t pad_val[32];
  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - value_len), value, value_len);
  bn_read_be(pad_val, &val);

  char amount[32];
  if (token == NULL) {
    if (bn_is_zero(&val)) {
      strcpy(amount, _("message"));
    } else {
      ethereumFormatAmount(&val, NULL, chain_id, amount, sizeof(amount));
    }
  } else {
    ethereumFormatAmount(&val, token, chain_id, amount, sizeof(amount));
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

  const char *address = addr;
  if (to_len && makerdao_isOasisDEXAddress(to, chain_id)) {
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
  }
}

static void layoutEthereumData(const uint8_t *data, uint32_t len,
                               uint32_t total_len, char *out_str,
                               size_t out_str_len) {
  char hexdata[3][17];
  char summary[20];
  uint32_t printed = 0;
  for (int i = 0; i < 3; i++) {
    uint32_t linelen = len - printed;
    if (linelen > 8) {
      linelen = 8;
    }
    data2hex(data, linelen, hexdata[i]);
    data += linelen;
    printed += linelen;
  }

  strcpy(summary, "...          bytes");
  char *p = summary + 11;
  uint32_t number = total_len;
  while (number > 0) {
    *p-- = '0' + number % 10;
    number = number / 10;
  }
  char *summarystart = summary;
  if (total_len == printed) summarystart = summary + 4;

  if ((uint32_t)snprintf(out_str, out_str_len, "%s%s\n%s%s", hexdata[0],
                         hexdata[1], hexdata[2], summarystart) >= out_str_len) {
    /*error detected.  Clear the buffer */
    memset(out_str, 0, out_str_len);
  }
}

static void formatEthereumFee(bignum256 *fee, const uint8_t *gas_price,
                              const uint8_t gas_price_len) {
  uint8_t pad_val[32];

  bn_zero(fee);
  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - gas_price_len), gas_price, gas_price_len);
  bn_read_be(pad_val, fee);
}

static void formatEthereumFeeEIP1559(
    bignum256 *fee, const uint8_t *max_fee_per_gas,
    const uint8_t max_fee_per_gas_len, const uint8_t *max_priority_fee_per_gas,
    const uint8_t max_priority_fee_per_gas_len) {
  bignum256 max_fee, max_pfee;
  uint8_t pad_val[32];

  bn_zero(fee);

  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - max_fee_per_gas_len), max_fee_per_gas,
         max_fee_per_gas_len);
  bn_read_be(pad_val, &max_fee);

  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - max_priority_fee_per_gas_len),
         max_priority_fee_per_gas, max_priority_fee_per_gas_len);
  bn_read_be(pad_val, &max_pfee);

  bn_add(fee, &max_fee);
  if (max_priority_fee_per_gas_len) {
    bn_add(fee, &max_pfee);
  }
}

static void layoutEthereumFee(const EthereumSignTx *msg, bool is_token,
                              char *out_str, size_t out_str_len) {
  bignum256 val, gas;
  char gas_value[32];
  char tx_value[32];
  uint8_t pad_val[32];

  memzero(gas_value, sizeof(gas_value));
  memzero(tx_value, sizeof(tx_value));

  if (msg->has_max_fee_per_gas) {
    formatEthereumFeeEIP1559(&val, msg->max_fee_per_gas.bytes,
                             msg->max_fee_per_gas.size,
                             msg->max_priority_fee_per_gas.bytes,
                             msg->max_priority_fee_per_gas.size);
  } else {
    formatEthereumFee(&val, msg->gas_price.bytes, msg->gas_price.size);
  }

  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - msg->gas_limit.size), msg->gas_limit.bytes,
         msg->gas_limit.size);
  bn_read_be(pad_val, &gas);
  bn_multiply(&val, &gas, &secp256k1.prime);
  ethereumFormatAmount(&gas, NULL, chain_id, gas_value, sizeof(gas_value));

  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - msg->value.size), msg->value.bytes, msg->value.size);
  bn_read_be(pad_val, &val);

  if (bn_is_zero(&val)) {
    strcpy(tx_value, is_token ? _("the tokens") : _("the message"));
  } else {
    ethereumFormatAmount(&val, NULL, chain_id, tx_value, sizeof(tx_value));
  }

  if ((uint32_t)snprintf(
          out_str, out_str_len,
          _("Send %s from your wallet, paying up to %s for gas?"), tx_value,
          gas_value) >= out_str_len) {
    /*error detected.  Clear the buffer */
    memset(out_str, 0, out_str_len);
  }
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

static bool ethereum_signing_check(EthereumSignTx *msg) {
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

  if (msg->gas_price.size + msg->gas_limit.size > 30) {
    // sanity check that fee doesn't overflow
    return false;
  }

  return true;
}

void ethereum_signing_init(EthereumSignTx *msg, const HDNode *node,
                           bool needs_confirm) {
  char confirm_body_message[121] = {0};

  ethereum_signing = true;
  sha3_256_Init(&keccak_ctx);

  memset(&msg_tx_request, 0, sizeof(EthereumTxRequest));
  /* set fields to 0, to avoid conditions later */
  if (!msg->has_value) msg->value.size = 0;
  if (!msg->has_data_initial_chunk) msg->data_initial_chunk.size = 0;
  if (!msg->has_to) msg->to.size = 0;
  if (!msg->has_nonce) msg->nonce.size = 0;

  /* eip-155 chain id */
  if (msg->has_chain_id) {
    if (msg->chain_id < 1) {
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Chain Id out of bounds"));
      ethereum_signing_abort();
      return;
    }
    chain_id = msg->chain_id;
  } else {
    chain_id = 0;
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

  const TokenType *token = NULL;

  // safety checks
  if (!ethereum_signing_check(msg)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Safety check failed"));
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

  // detect ERC-20 token
  if (data_total == 68 && ethereum_isStandardERC20Transfer(msg)) {
    token = tokenByChainAddress(chain_id, msg->to.bytes);
  }

  bool is_approve = false;
  if (data_total == 68 && ethereum_isStandardERC20Approve(msg)) {
    token = tokenByChainAddress(chain_id, msg->to.bytes);
    is_approve = true;
  }

  if (needs_confirm) {
    if (token != NULL) {
      layoutEthereumConfirmTx(
          msg->data_initial_chunk.bytes + 16, 20,
          msg->data_initial_chunk.bytes + 36, 32, token, confirm_body_message,
          sizeof(confirm_body_message), /*approve=*/is_approve);
    } else {
      layoutEthereumConfirmTx(msg->to.bytes, msg->to.size, msg->value.bytes,
                              msg->value.size, NULL, confirm_body_message,
                              sizeof(confirm_body_message), /*approve=*/false);
    }
    bool is_transfer = msg->address_type == OutputAddressType_TRANSFER;
    const char *title;
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
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Signing cancelled by user");
      ethereum_signing_abort();
      return;
    }
  }

  memset(confirm_body_message, 0, sizeof(confirm_body_message));
  if (token == NULL && data_total > 0 && data_needs_confirm) {
    // KeepKey custom: warn the user that they're trying to do something
    // that is potentially dangerous. People (generally) aren't great at
    // parsing raw transaction data, and we can't effectively show them
    // what they're about to do in the general case.
    if (!storage_isPolicyEnabled("AdvancedMode")) {
      (void)review(
          ButtonRequestType_ButtonRequest_Other, "Warning",
          "Signing of arbitrary ETH contract data is recommended only for "
          "experienced users. Enable 'AdvancedMode' policy to dismiss.");
    }

    layoutEthereumData(msg->data_initial_chunk.bytes,
                       msg->data_initial_chunk.size, data_total,
                       confirm_body_message, sizeof(confirm_body_message));
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Confirm Ethereum Data", "%s", confirm_body_message)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      ethereum_signing_abort();
      return;
    }
  }

  if (is_approve) {
    token = NULL;
  }

  memset(confirm_body_message, 0, sizeof(confirm_body_message));
  layoutEthereumFee(msg, token != NULL, confirm_body_message,
                    sizeof(confirm_body_message));
  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Transaction", "%s",
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
    // This is the chain ID length for 1559 tx (only one byte for now)
    rlp_length += rlp_calculate_number_length(chain_id);

    //rlp_length += 1;
  }

  rlp_length += rlp_calculate_length(msg->nonce.size, msg->nonce.bytes[0]);
  if (msg->has_max_fee_per_gas) {
    if (msg->has_max_priority_fee_per_gas) {
      rlp_length += rlp_calculate_length(msg->max_priority_fee_per_gas.size,
                                         msg->max_priority_fee_per_gas.bytes[0]);
    }
    rlp_length += rlp_calculate_length(msg->max_fee_per_gas.size,
                                       msg->max_fee_per_gas.bytes[0]);    
  } else {
    rlp_length += rlp_calculate_length(msg->gas_price.size, msg->gas_price.bytes[0]);
  }

  rlp_length += rlp_calculate_length(msg->gas_limit.size, msg->gas_limit.bytes[0]);
  rlp_length += rlp_calculate_length(msg->to.size, msg->to.bytes[0]);
  rlp_length += rlp_calculate_length(msg->value.size, msg->value.bytes[0]);
  rlp_length += rlp_calculate_length(data_total, msg->data_initial_chunk.bytes[0]);
    
  if (ethereum_tx_type == ETHEREUM_TX_TYPE_EIP_1559) {
    // access list size
    rlp_length += 1;  // c0, keepkey does not support >0 length access list at this time
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
  // keccak256(0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, 
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
    // chain id goes here for 1559 (only one byte for now)
    hash_rlp_field((uint8_t *)(&chain_id), sizeof(uint8_t));
  }

  hash_rlp_field(msg->nonce.bytes, msg->nonce.size);
    
  if (msg->has_max_fee_per_gas) {
    if (msg->has_max_priority_fee_per_gas) {
      hash_rlp_field(msg->max_priority_fee_per_gas.bytes,
                     msg->max_priority_fee_per_gas.size);
    }
    hash_rlp_field(msg->max_fee_per_gas.bytes, msg->max_fee_per_gas.size);
  } else {
    hash_rlp_field(msg->gas_price.bytes, msg->gas_price.size);
  }
    
  hash_rlp_field(msg->gas_limit.bytes, msg->gas_limit.size);
  hash_rlp_field(msg->to.bytes, msg->to.size);
  hash_rlp_field(msg->value.bytes, msg->value.size);
  hash_rlp_length(data_total, msg->data_initial_chunk.bytes[0]);
  hash_data(msg->data_initial_chunk.bytes, msg->data_initial_chunk.size);
  data_left = data_total - msg->data_initial_chunk.size;

  if (ethereum_tx_type == ETHEREUM_TX_TYPE_EIP_1559) {
    // Keepkey does not support an access list size >0 at this time
    uint8_t datbuf[1] = {0xC0};   // size of empty access list
    hash_data(datbuf, sizeof(datbuf));
  }

  memcpy(privkey, node->private_key, 32);

  if (data_left > 0) {
    send_request_chunk();
  } else {
    send_signature();
  }
}

void ethereum_signing_txack(EthereumTxAck *tx) {
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

  hash_data(tx->data_chunk.bytes, tx->data_chunk.size);

  data_left -= tx->data_chunk.size;

  if (data_left > 0) {
    send_request_chunk();
  } else {
    send_signature();
  }
}

void ethereum_signing_abort(void) {
  if (ethereum_signing) {
    memzero(privkey, sizeof(privkey));
    layoutHome();
    ethereum_signing = false;
  }
}

static void ethereum_message_hash(const uint8_t *message, size_t message_len,
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

void ethereum_message_sign(const EthereumSignMessage *msg, const HDNode *node,
                           EthereumMessageSignature *resp) {
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

int ethereum_message_verify(const EthereumVerifyMessage *msg) {
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
  sha3_Update(&ctx, (const uint8_t *)"\x19\x01", 2);
  sha3_Update(&ctx, domain_separator_hash, 32);
  if (has_message_hash) {
    sha3_Update(&ctx, message_hash, 32);
  }
  keccak_Final(&ctx, hash);
}

static int eip712_sign(const uint8_t *ds_hash, const uint8_t *msg_hash, bool has_msg_hash, 
                        const HDNode *node, uint8_t *v, uint8_t *sig) {

  uint8_t hash[32] = {0};

  ethereum_typed_hash(ds_hash, msg_hash, has_msg_hash, hash);

  return ecdsa_sign_digest(&secp256k1, node->private_key, hash, sig, v, ethereum_is_canonic);
}

void ethereum_typed_hash_sign(const EthereumSignTypedHash *msg,
                              const HDNode *node,
                              EthereumTypedDataSignature *resp) {

  uint8_t v = 0;
  if (0 != eip712_sign(msg->domain_separator_hash.bytes, msg->message_hash.bytes, 
              msg->has_message_hash, node, &v, resp->signature.bytes)) {
    fsm_sendFailure(FailureType_Failure_Other, _("EIP-712 hash signing failed"));
    return;
  }

  resp->signature.bytes[64] = 27 + v;
  resp->signature.size = 65;
  msg_write(MessageType_MessageType_EthereumTypedDataSignature, resp);
}

void failMessage(int err);

const char *failMsgReturn[LAST_ERROR - 2] = {
                        "EIP-712 general error",                              //  3
                        "EIP-712 user defined type name too long",
                        "EIP-712 too many user defined types",
                        "EIP-712 user defined type array name error",
                        "EIP-712 address string overflow",
                        "EIP-712 bytesN string overflow",
                        "EIP-712 bytesN size error",
                        "EIP-712 INT and UINT array parsing not implemented",
                        "EIP-712 bytesN array parsing not implemented",
                        "EIP-712 boolean array parsing not implemented",    
                        "EIP-712 not enough memory to parse message",         // 13
                        "EIP-712 primaryType name error",
                        "EIP-712 primaryType value error",
                        "EIP-712 types property error",
                        "EIP-712 typeS (typestring) property error",
                        "EIP-712 domain property name error",
                        "EIP-712 domain seperator hash must be calculated first",
                        "EIP-712 message property name error",
                        "EIP-712 primary type object error",
                        "EIP-712 typeS not found in eip712types",
                        "EIP-712 typeS name missing",                         // 23
                        "EIP-712 unused error 24",
                        "EIP-712 pairs are NULL",
                        "EIP-712 json pair type is not JSON_TEXT",
                        "EIP-712 pair does not have a sibling",
                        "EIP-712 typeType not encodable, possibly NULL",
                        "EIP-712 pair value is NULL",
                        "EIP-712 pair name is NULL",
                        "EIP-712 typeType has no name in parseVals",
                        "EIP-712 address string is NULL",
                        "EIP-712 no value for type during walkVals",          // 33
                        };

void failMessage(int err) {
  if (err < GENERAL_ERROR || err > LAST_ERROR) {
    // unknown error number
    fsm_sendFailure(FailureType_Failure_Other, _("EIP-712 unknown failure"));
  } else {
    fsm_sendFailure(FailureType_Failure_Other, _(failMsgReturn[err-3]));
  }
  return;
}


void e712_types_values(Ethereum712TypesValues *msg, EthereumTypedDataSignature *resp, const HDNode *node) {
  int errRet = SUCCESS;
  json_t memTypes[JSON_OBJ_POOL_SIZE] = {0};
  json_t memVals[JSON_OBJ_POOL_SIZE] = {0};
  json_t memPType[4] = {0};
  json_t const* jsonT;
  json_t const* jsonV;
  json_t const* jsonPT;
  char *typesJsonStr;
  char *primaryTypeJsonStr;
  char *valuesJsonStr;
  const char *primeType;
  json_t const* obTest;
  static uint8_t domainSeparatorHash[32]={0};
  static uint8_t messageHash[32]={0};
  static bool have_ds=false;

  typesJsonStr = msg->eip712types;
  primaryTypeJsonStr = msg->eip712primetype;
  valuesJsonStr = msg->eip712data;

  jsonT = json_create(typesJsonStr, memTypes, sizeof memTypes / sizeof *memTypes );
  jsonPT = json_create(primaryTypeJsonStr, memPType, sizeof memPType / sizeof *memPType );
  jsonV = json_create(valuesJsonStr, memVals, sizeof memVals / sizeof *memVals );

  if (!jsonT) {
    fsm_sendFailure(FailureType_Failure_Other, _("EIP-712 type property data error"));
    return;
  } 
  if (!jsonPT) {
    fsm_sendFailure(FailureType_Failure_Other, _("EIP-712 primaryType property data error"));
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
    if ((int)SUCCESS != (errRet = 
      encode(jsonT, jsonV, "EIP712Domain", resp->domain_separator_hash.bytes)
    )) {
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
    if (0 == (primeType = json_getValue(obTest))) {
      failMessage(JSON_PTYPEVALERR);
      return;
    }
    if (0 != strncmp(primeType, "EIP712Domain", strlen(primeType))) { // if primaryType is "EIP712Domain", message hash is NULL
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

    uint8_t v = 0;
    if (0 != eip712_sign(domainSeparatorHash, messageHash, resp->has_msg_hash, node, &v, resp->signature.bytes)) {
      fsm_sendFailure(FailureType_Failure_Other, _("EIP-712 typed hash signing failed"));
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

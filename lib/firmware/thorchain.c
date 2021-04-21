#include "keepkey/firmware/thorchain.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/tendermint.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/segwit_addr.h"

#include <stdbool.h>
#include <time.h>

static CONFIDENTIAL HDNode node;
static SHA256_CTX ctx;
static bool has_message;
static bool initialized;
static uint32_t msgs_remaining;
static ThorchainSignTx msg;
static bool testnet;

const ThorchainSignTx *thorchain_getThorchainSignTx(void) { return &msg; }

bool thorchain_signTxInit(const HDNode *_node, const ThorchainSignTx *_msg) {
  initialized = true;
  msgs_remaining = _msg->msg_count;
  has_message = false;
  testnet = false;

  if (_msg->has_testnet) {
    testnet = _msg->testnet;
  }

  memzero(&node, sizeof(node));
  memcpy(&node, _node, sizeof(node));
  memcpy(&msg, _msg, sizeof(msg));

  bool success = true;
  char buffer[64 + 1];

  sha256_Init(&ctx);

  // Each segment guaranteed to be less than or equal to 64 bytes
  // 19 + ^20 + 1 = ^40
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "{\"account_number\":\"%" PRIu64 "\"",
                                 msg.account_number);

  // <escape chain_id>
  const char *const chainid_prefix = ",\"chain_id\":\"";
  sha256_Update(&ctx, (uint8_t *)chainid_prefix, strlen(chainid_prefix));
  tendermint_sha256UpdateEscaped(&ctx, msg.chain_id, strlen(msg.chain_id));

  // 30 + ^10 + 19 = ^59
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "\",\"fee\":{\"amount\":[{\"amount\":\"%" PRIu32
                          "\",\"denom\":\"rune\"}]",
                          msg.fee_amount);

  // 8 + ^10 + 2 = ^20
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"gas\":\"%" PRIu32 "\"}", msg.gas);

  // <escape memo>
  const char *const memo_prefix = ",\"memo\":\"";
  sha256_Update(&ctx, (uint8_t *)memo_prefix, strlen(memo_prefix));
  if (msg.has_memo) {
    tendermint_sha256UpdateEscaped(&ctx, msg.memo, strlen(msg.memo));
  }

  // 10
  sha256_Update(&ctx, (uint8_t *)"\",\"msgs\":[", 10);

  return success;
}

bool thorchain_signTxUpdateMsgSend(const uint64_t amount,
                                   const char *to_address) {
  char mainnetp[] = "thor";
  char testnetp[] = "tthor";
  char *pfix;
  char buffer[64 + 1];

  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];
  if (!bech32_decode(hrp, decoded, &decoded_len, to_address)) {
    return false;
  }

  char from_address[46];

  pfix = mainnetp;
  if (testnet) {
    pfix = testnetp;
  }

  if (!tendermint_getAddress(&node, pfix, from_address)) {
    return false;
  }

  if (has_message) {
    sha256_Update(&ctx, (uint8_t *)",", 1);
  }

  bool success = true;

  const char *const prelude = "{\"type\":\"thorchain/MsgSend\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  // 21 + ^20 + 19 = ^60
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "\"amount\":[{\"amount\":\"%" PRIu64 "\",\"denom\":\"rune\"}]", amount);

  // 17 + 45 + 1 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"from_address\":\"%s\"", from_address);

  // 15 + 45 + 3 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"to_address\":\"%s\"}}", to_address);

  has_message = true;
  msgs_remaining--;
  return success;
}

bool thorchain_signTxFinalize(uint8_t *public_key, uint8_t *signature) {
  char buffer[64 + 1];

  // 16 + ^20 = ^36
  if (!tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                           "],\"sequence\":\"%" PRIu64 "\"}", msg.sequence))
    return false;

  hdnode_fill_public_key(&node);
  memcpy(public_key, node.public_key, 33);

  uint8_t hash[SHA256_DIGEST_LENGTH];
  sha256_Final(&ctx, hash);
  return ecdsa_sign_digest(&secp256k1, node.private_key, hash, signature, NULL,
                           NULL) == 0;
}

bool thorchain_signingIsInited(void) { return initialized; }

bool thorchain_signingIsFinished(void) { return msgs_remaining == 0; }

void thorchain_signAbort(void) {
  initialized = false;
  has_message = false;
  msgs_remaining = 0;
  memzero(&msg, sizeof(msg));
  memzero(&node, sizeof(node));
}

bool thorchain_parseConfirmMemo(const char *swapStr, size_t size) {
  /*
    Input: swapStr is candidate thorchain data
           size is the size of swapStr (<= 256)
    Memos should be of the form:
    transaction:chain.ticker-id:destination:limit
                ^^^^^^^^^^^^^^----------asset

    So, swap USDT to dest address 0x41e55..., limit 420
    SWAP:ETH.USDT-0xdac17f958d2ee523a2206206994597c13d831ec7:0x41e5560054824ea6b0732e656e3ad64e20e94e45:420

    Swap transactions can be indicated by "SWAP" or "s" or "="
  */

  char *parseTokPtrs[7] = {NULL, NULL, NULL, NULL,
                           NULL, NULL, NULL};  // we can parse up to 7 tokens
  char *tok;
  char memoBuf[256];
  uint16_t ctr;

  // check if memo data is recognized

  if (size > 256) return false;
  memzero(memoBuf, sizeof(memoBuf));
  strncpy(memoBuf, swapStr, size);
  memoBuf[255] = '\0';  // ensure null termination
  tok = strtok(memoBuf, ":");

  // get transaction and asset
  for (ctr = 0; ctr < 3; ctr++) {
    if (tok != NULL) {
      parseTokPtrs[ctr] = tok;
      tok = strtok(NULL, ":.");
    } else {
      break;
    }
  }

  if (ctr != 3) {
    // Must have three tokens at this point: transaction, chain, asset. If
    // not, just confirm data
    return false;
  }

  // Check for swap
  if (strncmp(parseTokPtrs[0], "SWAP", 4) == 0 || *parseTokPtrs[0] == 's' ||
      *parseTokPtrs[0] == '=') {
    // This is a swap, set up destination and limit
    // This is the dest, may be blank which means swap to self
    parseTokPtrs[3] = "self";
    parseTokPtrs[4] = "none";
    if (tok != NULL) {
      if ((uint32_t)(tok - (parseTokPtrs[2] + strlen(parseTokPtrs[2]))) == 1) {
        // has dest address
        parseTokPtrs[3] = tok;
        tok = strtok(NULL, ":");
      }
      if (tok != NULL) {
        // has limit
        parseTokPtrs[4] = tok;
      }
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain swap", "Confirm swap asset %s\n on chain %s", parseTokPtrs[2], parseTokPtrs[1])) {
      return false;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain swap", "Confirm to %s", parseTokPtrs[3])) {
      return false;
    }
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain swap", "Confirm limit %s", parseTokPtrs[4])) {
      return false;
    }
    return true;
  }

  // Check for add liquidity
  else if (strncmp(parseTokPtrs[0], "ADD", 3) == 0 || *parseTokPtrs[0] == 'a' ||
           *parseTokPtrs[0] == '+') {
    if (tok != NULL) {
      // add liquidity pool address
      parseTokPtrs[3] = tok;
    } 

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain add liquidity", "Confirm add asset %s\n on chain %s pool",
                 parseTokPtrs[2], parseTokPtrs[1])) {
      return false;
    }
    if (tok != NULL) {
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain add liquidity", "Confirm to %s", parseTokPtrs[3])) {
        return false;
      }
    }
    return true;
  }

  // Check for withdraw liquidity
  else if (strncmp(parseTokPtrs[0], "WITHDRAW", 8) == 0 || strncmp(parseTokPtrs[0], "wd", 2) == 0 ||
           *parseTokPtrs[0] == '-') {
    if (tok != NULL) {
      // add liquidity pool address
      parseTokPtrs[3] = tok;
    } 

    float percent = (float)(atoi(parseTokPtrs[3])) / 100;
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                 "Thorchain withdraw liquidity", "Confirm withdraw %3.2f%% of asset %s on chain %s",
                 percent, parseTokPtrs[2], parseTokPtrs[1])) {
      return false;
    }
    return true;

  } else {
    // Just confirm whatever coin data if no thorchain intention data parsable
    return false;
  }
}
#include "keepkey/firmware/binance.h"

#include "keepkey/firmware/tendermint.h"
#include "hwcrypto/crypto/memzero.h"
#include "hwcrypto/crypto/secp256k1.h"
#include "hwcrypto/crypto/segwit_addr.h"

#include "messages-binance.pb.h"

static CONFIDENTIAL HDNode node;
static SHA256_CTX ctx;
static bool has_message;
static bool initialized;
static uint32_t msgs_remaining;
static BinanceSignTx msg;

const BinanceSignTx *binance_getBinanceSignTx(void) { return &msg; }

bool binance_signTxInit(const HDNode *_node, const BinanceSignTx *_msg) {
  initialized = true;
  msgs_remaining = _msg->msg_count;
  has_message = false;

  memzero(&node, sizeof(node));
  memcpy(&node, _node, sizeof(node));
  memcpy(&msg, _msg, sizeof(msg));

  bool success = true;
  char buffer[64 + 1];

  sha256_Init(&ctx);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "{\"account_number\":\"%" PRIu64 "\"",
                                 msg.account_number);

  const char *const chainid_prefix = ",\"chain_id\":\"";
  sha256_Update(&ctx, (uint8_t *)chainid_prefix, strlen(chainid_prefix));
  tendermint_sha256UpdateEscaped(&ctx, msg.chain_id, strlen(msg.chain_id));

  const char *const data_memo = "\",\"data\":null,\"memo\":\"";
  sha256_Update(&ctx, (uint8_t *)data_memo, strlen(data_memo));
  if (msg.has_memo) {
    tendermint_sha256UpdateEscaped(&ctx, msg.memo, strlen(msg.memo));
  }

  sha256_Update(&ctx, (const uint8_t *)"\",\"msgs\":[", 10);
  return success;
}

bool binance_serializeCoin(const BinanceCoin *coin) {
  bool success = true;
  char buffer[64 + 1];

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "{\"amount\":%" PRIu64 ",\"denom\":\"%s\"}",
                                 coin->amount, coin->denom);

  return success;
}

bool binance_serializeInputOutput(const BinanceInputOutput *io) {
  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];
  if (!bech32_decode(hrp, decoded, &decoded_len, io->address)) {
    return false;
  }

  sha256_Update(&ctx, (const uint8_t *)"{\"address\":\"", 12);
  sha256_Update(&ctx, (const uint8_t *)io->address, strlen(io->address));
  sha256_Update(&ctx, (const uint8_t *)"\",\"coins\":[", 11);

  bool success = true;
  for (int i = 0; i < io->coins_count; i++) {
    success &= binance_serializeCoin(&io->coins[i]);
    if (i + 1 != io->coins_count) sha256_Update(&ctx, (const uint8_t *)",", 1);
  }

  sha256_Update(&ctx, (const uint8_t *)"]}", 2);

  return success;
}

bool binance_signTxUpdateTransfer(const BinanceTransferMsg *_msg) {
  bool success = true;

  sha256_Update(&ctx, (const uint8_t *)"{\"inputs\":[", 11);

  for (int i = 0; i < _msg->inputs_count; i++) {
    success &= binance_serializeInputOutput(&_msg->inputs[i]);
    if (i + 1 != _msg->inputs_count)
      sha256_Update(&ctx, (const uint8_t *)",", 1);
  }

  sha256_Update(&ctx, (const uint8_t *)"],\"outputs\":[", 13);

  for (int i = 0; i < _msg->outputs_count; i++) {
    success &= binance_serializeInputOutput(&_msg->outputs[i]);
    if (i + 1 != _msg->outputs_count)
      sha256_Update(&ctx, (const uint8_t *)",", 1);
  }

  sha256_Update(&ctx, (const uint8_t *)"]}", 2);

  has_message = true;
  msgs_remaining--;
  return success;
}

bool binance_signTxFinalize(uint8_t *public_key, uint8_t *signature) {
  char buffer[64 + 1];

  if (!tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                           "],\"sequence\":\"%" PRIu64
                           "\",\"source\":\"%" PRIu64 "\"}",
                           msg.sequence, msg.source))
    return false;

  hdnode_fill_public_key(&node);
  memcpy(public_key, node.public_key, 33);

  uint8_t hash[SHA256_DIGEST_LENGTH];
  sha256_Final(&ctx, hash);
  return ecdsa_sign_digest(&secp256k1, node.private_key, hash, signature, NULL,
                           NULL) == 0;
}

bool binance_signingIsInited(void) { return initialized; }

bool binance_signingIsFinished(void) { return msgs_remaining == 0; }

void binance_signAbort(void) {
  initialized = false;
  has_message = false;
  msgs_remaining = 0;
  memzero(&msg, sizeof(msg));
  memzero(&node, sizeof(node));
}

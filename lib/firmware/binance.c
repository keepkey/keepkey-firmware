#include "keepkey/firmware/binance.h"

#include "keepkey/firmware/tendermint.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/secp256k1.h"
#include "trezor/crypto/segwit_addr.h"

#include "messages-binance.pb.h"

static CONFIDENTIAL HDNode node;
static SHA256_CTX ctx;
static bool has_message;
static bool initialized;
static uint32_t msgs_remaining;
static BinanceSignTx msg;

const BinanceSignTx* binance_getBinanceSignTx(void) { return &msg; }

bool binance_isValidDenom(const char* denom) {
  if (!denom) return false;
  const size_t len = strnlen(denom, BINANCE_MAX_DENOM_LEN + 1);
  if (len == 0 || len > BINANCE_MAX_DENOM_LEN) return false;
  for (size_t i = 0; i < len; i++) {
    const char c = denom[i];
    if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'))
      return false;
  }
  return true;
}

bool binance_validateTransfer(const BinanceTransferMsg* transfer) {
  if (!transfer || transfer->inputs_count != 1 ||
      transfer->inputs[0].coins_count != 1 || transfer->outputs_count != 1 ||
      transfer->outputs[0].coins_count != 1)
    return false;

  const BinanceInputOutput* input = &transfer->inputs[0];
  const BinanceInputOutput* output = &transfer->outputs[0];
  const BinanceCoin* input_coin = &input->coins[0];
  const BinanceCoin* output_coin = &output->coins[0];
  if (!input->has_address || !output->has_address || !input_coin->has_amount ||
      !output_coin->has_amount || !input_coin->has_denom ||
      !output_coin->has_denom || input_coin->amount <= 0 ||
      output_coin->amount <= 0 || input_coin->amount != output_coin->amount ||
      strcmp(input_coin->denom, output_coin->denom) != 0 ||
      !binance_isValidDenom(input_coin->denom))
    return false;

  return true;
}

bool binance_signTxInit(const HDNode* _node, const BinanceSignTx* _msg) {
  binance_signAbort();
  if (!_node || !_msg || !_msg->has_msg_count || _msg->msg_count == 0 ||
      !_msg->has_account_number || _msg->account_number < 0 ||
      !_msg->has_chain_id || _msg->chain_id[0] == '\0' || !_msg->has_sequence ||
      _msg->sequence < 0 || !_msg->has_source || _msg->source < 0)
    return false;

  msgs_remaining = _msg->msg_count;

  memcpy(&node, _node, sizeof(node));
  memcpy(&msg, _msg, sizeof(msg));

  bool success = true;
  char buffer[64 + 1];

  sha256_Init(&ctx);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "{\"account_number\":\"%" PRIu64 "\"",
                                 (uint64_t)msg.account_number);

  const char* const chainid_prefix = ",\"chain_id\":\"";
  sha256_Update(&ctx, (uint8_t*)chainid_prefix, strlen(chainid_prefix));
  tendermint_sha256UpdateEscaped(&ctx, msg.chain_id, strlen(msg.chain_id));

  const char* const data_memo = "\",\"data\":null,\"memo\":\"";
  sha256_Update(&ctx, (uint8_t*)data_memo, strlen(data_memo));
  if (msg.has_memo) {
    tendermint_sha256UpdateEscaped(&ctx, msg.memo, strlen(msg.memo));
  }

  sha256_Update(&ctx, (const uint8_t*)"\",\"msgs\":[", 10);
  if (!success) {
    binance_signAbort();
    return false;
  }
  initialized = true;
  return true;
}

bool binance_serializeCoin(const BinanceCoin* coin) {
  if (!coin || !coin->has_amount || coin->amount <= 0 || !coin->has_denom ||
      !binance_isValidDenom(coin->denom))
    return false;

  bool success = true;
  char buffer[64 + 1];

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "{\"amount\":%" PRIu64 ",\"denom\":\"%s\"}",
                                 (uint64_t)coin->amount, coin->denom);

  return success;
}

bool binance_serializeInputOutput(const BinanceInputOutput* io) {
  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];
  if (!bech32_decode(hrp, decoded, &decoded_len, io->address)) {
    return false;
  }

  sha256_Update(&ctx, (const uint8_t*)"{\"address\":\"", 12);
  sha256_Update(&ctx, (const uint8_t*)io->address, strlen(io->address));
  sha256_Update(&ctx, (const uint8_t*)"\",\"coins\":[", 11);

  bool success = true;
  for (int i = 0; i < io->coins_count; i++) {
    success &= binance_serializeCoin(&io->coins[i]);
    if (i + 1 != io->coins_count) sha256_Update(&ctx, (const uint8_t*)",", 1);
  }

  sha256_Update(&ctx, (const uint8_t*)"]}", 2);

  return success;
}

bool binance_signTxUpdateTransfer(const BinanceTransferMsg* _msg) {
  if (!initialized || msgs_remaining == 0 || !binance_validateTransfer(_msg))
    return false;

  bool success = true;

  sha256_Update(&ctx, (const uint8_t*)"{\"inputs\":[", 11);

  for (int i = 0; i < _msg->inputs_count; i++) {
    success &= binance_serializeInputOutput(&_msg->inputs[i]);
    if (i + 1 != _msg->inputs_count)
      sha256_Update(&ctx, (const uint8_t*)",", 1);
  }

  sha256_Update(&ctx, (const uint8_t*)"],\"outputs\":[", 13);

  for (int i = 0; i < _msg->outputs_count; i++) {
    success &= binance_serializeInputOutput(&_msg->outputs[i]);
    if (i + 1 != _msg->outputs_count)
      sha256_Update(&ctx, (const uint8_t*)",", 1);
  }

  sha256_Update(&ctx, (const uint8_t*)"]}", 2);

  if (success) {
    has_message = true;
    msgs_remaining--;
  }
  return success;
}

bool binance_signTxFinalize(uint8_t* public_key, uint8_t* signature) {
  if (!initialized || msgs_remaining != 0 || !has_message || !public_key ||
      !signature)
    return false;
  char buffer[64 + 1];

  if (!tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                           "],\"sequence\":\"%" PRIu64
                           "\",\"source\":\"%" PRIu64 "\"}",
                           (uint64_t)msg.sequence, (uint64_t)msg.source))
    return false;

  hdnode_fill_public_key(&node);
  memcpy(public_key, node.public_key, 33);

  uint8_t hash[SHA256_DIGEST_LENGTH];
  sha256_Final(&ctx, hash);
  return ecdsa_sign_digest(&secp256k1, node.private_key, hash, signature, NULL,
                           NULL) == 0;
}

bool binance_signingIsInited(void) { return initialized; }

bool binance_signingIsFinished(void) {
  return initialized && msgs_remaining == 0 && has_message;
}

void binance_signAbort(void) {
  initialized = false;
  has_message = false;
  msgs_remaining = 0;
  memzero(&msg, sizeof(msg));
  memzero(&node, sizeof(node));
}

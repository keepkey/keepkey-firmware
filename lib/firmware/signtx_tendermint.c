/*
 * This file is part of the Keepkey project.
 *
 * Copyright (C) 2021 Shapeshift
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

#include "keepkey/firmware/cosmos.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/signtx_tendermint.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/tendermint.h"
#include "hwcrypto/crypto/secp256k1.h"
#include "hwcrypto/crypto/ecdsa.h"
#include "hwcrypto/crypto/memzero.h"
#include "hwcrypto/crypto/segwit_addr.h"

#include <stdbool.h>
#include <time.h>

static CONFIDENTIAL HDNode node;
static SHA256_CTX ctx;
static bool has_message;
static bool initialized;
static uint32_t msgs_remaining;
static TendermintSignTx tmsg;

const void *tendermint_getSignTx(void) { return (void *)&tmsg; }

bool tendermint_signTxInit(const HDNode *_node, const void *_msg,
                           const size_t msgsize, const char *denom) {
  initialized = true;
  msgs_remaining = ((TendermintSignTx *)_msg)->msg_count;
  has_message = false;

  memzero(&node, sizeof(node));
  memcpy(&node, _node, sizeof(node));

  /*
    _msg is expected to be of type TendermintSignTx, CosmosSignTx or
    ThorchainSignTx. These messages all have common overlapping fields with
    TendermintSignTx having extra parameters. Copy the _msg memory into a static
    TendermintSignTx type and parse from there.
  */

  if (msgsize > sizeof(tmsg)) {
    return false;
  }

  if (strnlen(denom, 10) > 9) {
    return false;
  }

  memcpy((void *)&tmsg, _msg, msgsize);

  bool success = true;
  char buffer[128];

  sha256_Init(&ctx);

  // Each segment guaranteed to be less than or equal to 64 bytes
  // 19 + ^20 + 1 = ^40
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "{\"account_number\":\"%" PRIu64 "\"",
                                 tmsg.account_number);

  // <escape chain_id>
  const char *const chainid_prefix = ",\"chain_id\":\"";
  sha256_Update(&ctx, (uint8_t *)chainid_prefix, strlen(chainid_prefix));
  tendermint_sha256UpdateEscaped(&ctx, tmsg.chain_id, strlen(tmsg.chain_id));

  // 30 + ^10 + 11 + ^9 + 3 = ^63
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "\",\"fee\":{\"amount\":[{\"amount\":\"%" PRIu32 "\",\"denom\":\"%s\"}]",
      tmsg.fee_amount, denom);

  // 8 + ^10 + 2 = ^20
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"gas\":\"%" PRIu32 "\"}", tmsg.gas);

  // <escape memo>
  const char *const memo_prefix = ",\"memo\":\"";
  sha256_Update(&ctx, (uint8_t *)memo_prefix, strlen(memo_prefix));
  if (tmsg.has_memo) {
    tendermint_sha256UpdateEscaped(&ctx, tmsg.memo, strlen(tmsg.memo));
  }

  // 10
  sha256_Update(&ctx, (uint8_t *)"\",\"msgs\":[", 10);

  return success;
}

bool tendermint_signTxUpdateMsgSend(const uint64_t amount,
                                    const char *to_address,
                                    const char *chainstr, const char *denom,
                                    const char *msgTypePrefix) {
  char buffer[128];
  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];

  if (!bech32_decode(hrp, decoded, &decoded_len, to_address)) {
    return false;
  }

  if (strnlen(msgTypePrefix, 25) > 24 || strnlen(denom, 10) > 9 ||
      strnlen(chainstr, 15) > 14) {
    return false;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54];
  if (!tendermint_getAddress(&node, chainstr, from_address)) {
    return false;
  }

  if (has_message) {
    sha256_Update(&ctx, (uint8_t *)",", 1);
  }

  bool success = true;

  // 9 + ^24 + 19 = ^52
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "{\"type\":\"%s/MsgSend\",\"value\":{",
                                 msgTypePrefix);

  // 21 + ^20 + 11 + ^9 + 3 = ^64
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":[{\"amount\":\"%" PRIu64
                                 "\",\"denom\":\"%s\"}]",
                                 amount, denom);

  // 17
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), ",\"from_address\":\"");

  // ^53 + 1 = ^54
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "%s\"", from_address);

  // 15
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), ",\"to_address\":\"");

  // ^53 + 3 = ^56
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "%s\"}}", to_address);

  has_message = true;
  msgs_remaining--;
  return success;
}

bool tendermint_signTxUpdateMsgDelegate(const uint64_t amount,
                                        const char *delegator_address,
                                        const char *validator_address,
                                        const char *chainstr, const char *denom,
                                        const char *msgTypePrefix) {
  char buffer[128];
  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];

  if (!bech32_decode(hrp, decoded, &decoded_len, delegator_address)) {
    return false;
  }

  if (strnlen(msgTypePrefix, 25) > 24 || strnlen(denom, 10) > 9 ||
      strnlen(chainstr, 15) > 14) {
    return false;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54];
  if (!tendermint_getAddress(&node, chainstr, from_address)) {
    return false;
  }

  if (has_message) {
    sha256_Update(&ctx, (uint8_t *)",", 1);
  }

  bool success = true;

  // 9 + ^24 + 23 = ^56
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "{\"type\":\"%s/MsgDelegate\",\"value\":{",
                                 msgTypePrefix);

  // 20 + ^20 + 11 + ^9 + 2 = ^62
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":{\"amount\":\"%" PRIu64
                                 "\",\"denom\":\"%s\"}",
                                 amount, denom);

  // 22
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"delegator_address\":\"");

  // ^53 + 3 = ^56
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "%s\",\"",
                                 delegator_address);

  // 20
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "validator_address\":\"");

  // ^53 + 3 = ^56
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "%s\"}}",
                                 validator_address);

  has_message = true;
  msgs_remaining--;
  return success;
}
bool tendermint_signTxUpdateMsgUndelegate(const uint64_t amount,
                                          const char *delegator_address,
                                          const char *validator_address,
                                          const char *chainstr,
                                          const char *denom,
                                          const char *msgTypePrefix) {
  char buffer[128];
  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];

  if (!bech32_decode(hrp, decoded, &decoded_len, delegator_address)) {
    return false;
  }

  if (strnlen(msgTypePrefix, 25) > 24 || strnlen(denom, 10) > 9 ||
      strnlen(chainstr, 15) > 14) {
    return false;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54];
  if (!tendermint_getAddress(&node, chainstr, from_address)) {
    return false;
  }

  if (has_message) {
    sha256_Update(&ctx, (uint8_t *)",", 1);
  }

  bool success = true;

  // 9 + ^24 + 25 = ^58
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "{\"type\":\"%s/MsgUndelegate\",\"value\":{",
                                 msgTypePrefix);

  // 20 + ^20 + 11 + ^9 + 2 = ^62
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":{\"amount\":\"%" PRIu64
                                 "\",\"denom\":\"%s\"}",
                                 amount, denom);

  // 22
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"delegator_address\":\"");

  // ^53 + 3 = ^56
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "%s\",\"",
                                 delegator_address);

  // 20
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "validator_address\":\"");

  // ^53 + 3 = ^56
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "%s\"}}",
                                 validator_address);

  has_message = true;
  msgs_remaining--;
  return success;
}

bool tendermint_signTxUpdateMsgRedelegate(
    const uint64_t amount, const char *delegator_address,
    const char *validator_src_address, const char *validator_dst_address,
    const char *chainstr, const char *denom, const char *msgTypePrefix) {
  char buffer[128];
  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];

  if (!bech32_decode(hrp, decoded, &decoded_len, delegator_address)) {
    return false;
  }

  if (strnlen(msgTypePrefix, 25) > 24 || strnlen(denom, 10) > 9 ||
      strnlen(chainstr, 15) > 14) {
    return false;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54];
  if (!tendermint_getAddress(&node, chainstr, from_address)) {
    return false;
  }

  if (has_message) {
    sha256_Update(&ctx, (uint8_t *)",", 1);
  }

  bool success = true;

  // 9 + ^24 + 28 = ^64
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "{\"type\":\"%s/MsgBeginRedelegate\",\"value\"", msgTypePrefix);

  // 22 + ^20 + 11 + ^9 + 2 = ^64
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ":{\"amount\":{\"amount\":\"%" PRIu64
                                 "\",\"denom\":\"%s\"}",
                                 amount, denom);

  // 22
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"delegator_address\":\"");

  // ^53 + 1 = ^54
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "%s",
                                 delegator_address);

  // 27
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\",\"validator_dst_address\":\"");

  // ^53
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "%s",
                                 validator_dst_address);

  // 27
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\",\"validator_src_address\":\"");

  // ^53 + 3 = ^56
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "%s\"}}",
                                 validator_src_address);

  has_message = true;
  msgs_remaining--;
  return success;
}

bool tendermint_signTxUpdateMsgRewards(const uint64_t *amount,
                                       const char *delegator_address,
                                       const char *validator_address,
                                       const char *chainstr, const char *denom,
                                       const char *msgTypePrefix) {
  char buffer[128];
  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];

  if (!bech32_decode(hrp, decoded, &decoded_len, delegator_address)) {
    return false;
  }

  if (strnlen(msgTypePrefix, 25) > 24 || strnlen(denom, 10) > 9 ||
      strnlen(chainstr, 15) > 14) {
    return false;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54];
  if (!tendermint_getAddress(&node, chainstr, from_address)) {
    return false;
  }

  if (has_message) {
    sha256_Update(&ctx, (uint8_t *)",", 1);
  }

  bool success = true;

  // 9 + ^24 + 38 = ^72
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "{\"type\":\"%s/MsgWithdrawDelegationReward\",\"value\":{",
      msgTypePrefix);

  // 20 + ^20 + 11 + ^9 + 3 = ^65
  if (amount != NULL) {
    success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                   "\"amount\":{\"amount\":\"%" PRIu64
                                   "\",\"denom\":\"%s\"},",
                                   *amount, denom);
  }

  // 21
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"delegator_address\":\"");

  // ^53 + 3 = ^56
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "%s\",\"",
                                 delegator_address);

  // 20
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "validator_address\":\"");

  // ^53 + 3 = ^56
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "%s\"}}",
                                 validator_address);

  has_message = true;
  msgs_remaining--;
  return success;
}

bool tendermint_signTxUpdateMsgIBCTransfer(
    const uint64_t amount, const char *sender, const char *receiver,
    const char *source_channel, const char *source_port,
    const char *revision_number, const char *revision_height,
    const char *chainstr, const char *denom, const char *msgTypePrefix) {
  char buffer[128];
  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];

  if (!bech32_decode(hrp, decoded, &decoded_len, receiver)) {
    return false;
  }

  if (strnlen(msgTypePrefix, 25) > 24 || strnlen(denom, 10) > 9 ||
      strnlen(chainstr, 15) > 14) {
    return false;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54];
  if (!tendermint_getAddress(&node, chainstr, from_address)) {
    return false;
  }

  if (has_message) {
    sha256_Update(&ctx, (uint8_t *)",", 1);
  }

  bool success = true;

  // 9 + ^24 + 23 = ^56
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "{\"type\":\"%s/MsgTransfer\",\"value\":{",
                                 msgTypePrefix);

  // 13
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"receiver\":\"");

  // ^53 + 1 = ^54
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "%s\"", receiver);

  // 11
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), ",\"sender\":\"");

  // ^53 + 1 = ^54
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "%s\"", sender);

  // 19 + ^32 + 1 = ^52
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"source_channel\":\"%s\"", source_channel);

  // 16 + ^32 + 2 = ^40
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"source_port\":\"%s\",", source_port);

  // 37 + ^16 = ^53
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"timeout_height\":{\"revision_height\":\"%s",
                                 revision_height);

  // 21 + ^9 + 3 = ^33
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "\",\"revision_number\":\"%s\"},", revision_number);

  // 20 + ^20 + 11 + ^9 + 3 = ^63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"token\":{\"amount\":\"%" PRIu64
                                 "\",\"denom\":\"%s\"}}}",
                                 amount, denom);

  has_message = true;
  msgs_remaining--;
  return success;
}

bool tendermint_signTxFinalize(uint8_t *public_key, uint8_t *signature) {
  char buffer[128];

  // 14 + ^20 + 2 = ^36
  if (!tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                           "],\"sequence\":\"%" PRIu64 "\"}", tmsg.sequence)) {
    return false;
  }

  hdnode_fill_public_key(&node);
  memcpy(public_key, node.public_key, 33);

  uint8_t hash[SHA256_DIGEST_LENGTH];
  sha256_Final(&ctx, hash);
  return ecdsa_sign_digest(&secp256k1, node.private_key, hash, signature, NULL,
                           NULL) == 0;
}

bool tendermint_signingIsInited(void) { return initialized; }

bool tendermint_signingIsFinished(void) { return msgs_remaining == 0; }

void tendermint_signAbort(void) {
  initialized = false;
  has_message = false;
  msgs_remaining = 0;
  memzero(&tmsg, sizeof(tmsg));
  memzero(&node, sizeof(node));
}
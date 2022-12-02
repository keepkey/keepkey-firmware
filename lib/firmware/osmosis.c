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

#include "keepkey/firmware/osmosis.h"
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
static bool initialized;
static uint32_t msgs_remaining;
static OsmosisSignTx msg;
static bool testnet;

const OsmosisSignTx *osmosis_getOsmosisSignTx(void) { return &msg; }

bool osmosis_signTxInit(const HDNode *_node, const OsmosisSignTx *_msg) {
  initialized = true;
  msgs_remaining = _msg->msg_count;
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
  if (!tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                           "{\"account_number\":\"%" PRIu64 "\"",
                           msg.account_number))
    return false;

  // <escape chain_id>
  const char *const chainid_prefix = ",\"chain_id\":\"";
  sha256_Update(&ctx, (uint8_t *)chainid_prefix, strlen(chainid_prefix));
  tendermint_sha256UpdateEscaped(&ctx, msg.chain_id, strlen(msg.chain_id));

  // 30 + ^10 + 19 = ^59
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "\",\"fee\":{\"amount\":[{\"amount\":\"%" PRIu32
                          "\",\"denom\":\"uosmo\"}]",
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

bool osmosis_signTxUpdateMsgLPAdd(const OsmosisMsgLPAdd msglpadd) {
  char buffer[96 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"osmosis/gamm/join-pool\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"pool_id\":\"%s\",", msglpadd.pool_id);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"sender\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 msglpadd.sender);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"share_out_amount\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"%" PRIu64 "\",", msglpadd.share_out_amount);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"token_in_maxs\":[{");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":\"%" PRIu64 "\",",
                                 msglpadd.amount_in_max_a);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"denom\":\"%s\"},", msglpadd.denom_in_max_a);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":\"%" PRIu64 "\",",
                                 msglpadd.amount_in_max_b);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"denom\":\"%s\"},", msglpadd.denom_in_max_b);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgLPRemove(const OsmosisMsgLPRemove msglpremove) {
  char buffer[96 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"osmosis/gamm/exit-pool\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"pool_id\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 msglpremove.pool_id);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"sender\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 msglpremove.sender);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"share_out_amount\":");

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%" PRIu64 "\",",
                          msglpremove.share_out_amount);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"token_out_mins\":[{");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":\"%" PRIu64 "\",",
                                 msglpremove.amount_out_min_a);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"denom\":\"%s\"},",
                          msglpremove.denom_out_min_a);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":\"%" PRIu64 "\",",
                                 msglpremove.amount_out_min_b);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"denom\":\"%s\"},",
                          msglpremove.denom_out_min_b);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgLPStake(const OsmosisMsgLPStake msgstake) {
  char buffer[96 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"osmosis/lockup/lock-tokens\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"coins\":[{");

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "\"amount\":\"%" PRIu64 "\",\"denom\":\"%s\"}],",
                          msgstake.amount, msgstake.denom);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"duration\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"%" PRIu64 "\",", msgstake.duration);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"owner\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 msgstake.owner);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgLPUnstake(const OsmosisMsgLPUnstake msgunstake) {
  char buffer[96 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"osmosis/lockup/begin-unlock-period-lock\",\"value\":";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "{\"ID\":\"%s\",", msgunstake.id);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"owner\":\"%s\"}}", msgunstake.owner);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgSwap(const OsmosisMsgSwap msgswap) {
  char buffer[96 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"osmosis/gamm/swap-exact-amount-in\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"routes\":[{");
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"pool_id\":%s\",", msgswap.pool_id);
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"token_out_denom\":%s\"}],",
                                 msgswap.token_out_denom);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"sender\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 msgswap.sender);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"token_in\":{");
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "\"amount\":%" PRIu64 "\",", msgswap.token_in_amount);
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"denom\":\"%s\"},", msgswap.token_in_denom);
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"token_out_min_amount\":\"%" PRIu64 "\"}}",
                                 msgswap.token_out_min_amount);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgSend(const uint64_t amount, const char *to_address,
                                 const char *denom) {
  char mainnetp[] = "osmo";
  char testnetp[] = "tosmo";
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

  bool success = true;

  const char *const prelude = "{\"type\":\"cosmos-sdk/MsgSend\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  // 21 + ^20 + 19 = ^60
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":[{\"amount\":\"%" PRIu64
                                 "\",\"denom\":\"%s\"}]",
                                 amount, denom);

  // 17 + 45 + 1 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"from_address\":\"%s\"", from_address);

  // 15 + 45 + 3 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"to_address\":\"%s\"}}", to_address);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgDelegate(const uint64_t amount,
                                     const char *delegator_address,
                                     const char *validator_address,
                                     const char *denom) {
  char mainnetp[] = "osmo";
  char testnetp[] = "tosmo";
  char *pfix;

  char buffer[128];
  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];

  if (!bech32_decode(hrp, decoded, &decoded_len, delegator_address)) {
    return false;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54];

  pfix = mainnetp;
  if (testnet) {
    pfix = testnetp;
  }

  if (!tendermint_getAddress(&node, pfix, from_address)) {
    return false;
  }

  bool success = true;

  // 9 + ^24 + 23 = ^56
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "{\"type\":\"cosmos-sdk/MsgDelegate\",\"value\":{");

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

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgUndelegate(const uint64_t amount,
                                       const char *delegator_address,
                                       const char *validator_address,
                                       const char *denom) {
  char mainnetp[] = "osmo";
  char testnetp[] = "tosmo";
  char *pfix;

  char buffer[128];
  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];

  if (!bech32_decode(hrp, decoded, &decoded_len, delegator_address)) {
    return false;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54];

  pfix = mainnetp;
  if (testnet) {
    pfix = testnetp;
  }
  if (!tendermint_getAddress(&node, pfix, from_address)) {
    return false;
  }

  bool success = true;

  // 9 + ^24 + 25 = ^58
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "{\"type\":\"cosmos-sdk/MsgUndelegate\",\"value\":{");

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

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgRedelegate(const uint64_t amount,
                                       const char *delegator_address,
                                       const char *validator_src_address,
                                       const char *validator_dst_address,
                                       const char *denom) {
  char mainnetp[] = "osmo";
  char testnetp[] = "tosmo";
  char *pfix;

  char buffer[128];
  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];

  if (!bech32_decode(hrp, decoded, &decoded_len, delegator_address)) {
    return false;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54];
  pfix = mainnetp;
  if (testnet) {
    pfix = testnetp;
  }
  if (!tendermint_getAddress(&node, pfix, from_address)) {
    return false;
  }

  bool success = true;

  // 9 + ^24 + 28 = ^64
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "{\"type\":\"cosmos-sdk/MsgBeginRedelegate\",\"value\"");

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

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgRewards(const uint64_t *amount,
                                    const char *delegator_address,
                                    const char *validator_address,
                                    const char *denom) {
  char mainnetp[] = "osmo";
  char testnetp[] = "tosmo";
  char *pfix;

  char buffer[128];
  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];

  if (!bech32_decode(hrp, decoded, &decoded_len, delegator_address)) {
    return false;
  }

  pfix = mainnetp;
  if (testnet) {
    pfix = testnetp;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54];
  if (!tendermint_getAddress(&node, pfix, from_address)) {
    return false;
  }

  bool success = true;

  // 9 + ^24 + 38 = ^72
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "{\"type\":\"cosmos-sdk/MsgWithdrawDelegationReward\",\"value\":{");

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

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgIBCTransfer(
    const uint64_t amount, const char *sender, const char *receiver,
    const char *source_channel, const char *source_port,
    const char *revision_number, const char *revision_height,
    const char *denom) {
  char mainnetp[] = "osmo";
  char testnetp[] = "tosmo";
  char *pfix;

  char buffer[128];
  size_t decoded_len;
  char hrp[45];
  uint8_t decoded[38];

  if (!bech32_decode(hrp, decoded, &decoded_len, receiver)) {
    return false;
  }

  pfix = mainnetp;
  if (testnet) {
    pfix = testnetp;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54];
  if (!tendermint_getAddress(&node, pfix, from_address)) {
    return false;
  }

  bool success = true;

  // 9 + ^24 + 23 = ^56
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "{\"type\":\"cosmos-sdk/MsgTransfer\",\"value\":{");

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

  msgs_remaining--;
  return success;
}

bool osmosis_signTxFinalize(uint8_t *public_key, uint8_t *signature) {
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

bool osmosis_signingIsInited(void) { return initialized; }

bool osmosis_signingIsFinished(void) { return msgs_remaining == 0; }

void osmosis_signAbort(void) {
  initialized = false;
  msgs_remaining = 0;
  memzero(&msg, sizeof(msg));
  memzero(&node, sizeof(node));
}

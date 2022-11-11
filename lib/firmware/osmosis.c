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

  // TODO: Check and see if account number and chain ID parameters are
  // valid/necessary here.

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
                          "\",\"denom\":\"osmo\"}]",
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

bool osmosis_signTxUpdateMsgSend(const uint64_t amount,
                                 const char *to_address) {
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
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "\"amount\":[{\"amount\":\"%" PRIu64 "\",\"denom\":\"uosmo\"}]", amount);

  // 17 + 45 + 1 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"from_address\":\"%s\"", from_address);

  // 15 + 45 + 3 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"to_address\":\"%s\"}}", to_address);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgDelegate(const OsmosisMsgDelegate *delegatemsg) {
  char buffer[64 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"cosmos-sdk/MsgDelegate\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":{\"amount\":\"%" PRIu64
                                 "\",\"denom\":\"%s\"},",
                                 delegatemsg->amount, delegatemsg->denom);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"delegator_address\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 delegatemsg->delegator_address);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"validator_address\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\"}}",
                                 delegatemsg->validator_address);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgUndelegate(
    const OsmosisMsgUndelegate *undelegatemsg) {
  char buffer[64 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"cosmos-sdk/MsgUndelegate\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":{\"amount\":\"%" PRIu64
                                 "\",\"denom\":\"%s\"},",
                                 undelegatemsg->amount, undelegatemsg->denom);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"delegator_address\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 undelegatemsg->delegator_address);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"validator_address\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\"}}",
                                 undelegatemsg->validator_address);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgLPAdd(const OsmosisMsgLPAdd *lpaddmsg) {
  char buffer[64 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"osmosis/gamm/join-pool\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"poolId\":\"%s\",", lpaddmsg->pool_id);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"sender\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 lpaddmsg->sender);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"shareOutAmount\":");

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%" PRIu64 "\",",
                          lpaddmsg->share_out_amount);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"tokenInMaxs\":[{");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":\"%" PRIu64 "\",",
                                 lpaddmsg->amount_in_max_a);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"denom\":\"%s\"},",
                          lpaddmsg->denom_in_max_a);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":\"%" PRIu64 "\",",
                                 lpaddmsg->amount_in_max_b);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"denom\":\"%s\"},",
                          lpaddmsg->denom_in_max_b);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgLPRemove(const OsmosisMsgLPRemove *lpremovemsg) {
  char buffer[64 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"osmosis/gamm/exit-pool\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"poolId\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 lpremovemsg->pool_id);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"sender\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 lpremovemsg->sender);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"shareOutAmount\":");

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%" PRIu64 "\",",
                          lpremovemsg->share_out_amount);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"tokenOutMins\":[{");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":\"%" PRIu64 "\",",
                                 lpremovemsg->amount_out_min_a);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"denom\":\"%s\"},",
                          lpremovemsg->denom_out_min_a);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":\"%" PRIu64 "\",",
                                 lpremovemsg->amount_out_min_b);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"denom\":\"%s\"},",
                          lpremovemsg->denom_out_min_b);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgLPStake(const OsmosisMsgLPStake *msgstake) {
  char buffer[64 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"osmosis/lockup/lock-tokens\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"coins\":[{");

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "\"amount\":\"%" PRIu64 "\",\"denom\":\"%s\"}],",
                          msgstake->amount, msgstake->denom);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"duration\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"%" PRIu64 "\",", msgstake->duration);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"owner\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 msgstake->owner);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgLPUnstake(const OsmosisMsgLPUnstake *msgunstake) {
  char buffer[64 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"osmosis/lockup/begin-unlock-period-lock\",\"value\":";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "{\"ID\":\"%s\",", msgunstake->id);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"owner\":\"%s\"}}", msgunstake->owner);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgRedelegate(
    const OsmosisMsgRedelegate *redelegatemsg) {
  char buffer[64 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"cosmos-sdk/MsgRedelegate\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":{\"amount\":\"%" PRIu64
                                 "\",\"denom\":\"%s\"},",
                                 redelegatemsg->amount, redelegatemsg->denom);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"delegator_address\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 redelegatemsg->delegator_address);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"validator_dst_address\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 redelegatemsg->validator_dst_address);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"validator_src_address\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\"}}",
                                 redelegatemsg->validator_src_address);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgRewards(const OsmosisMsgRewards *rewardsmsg) {
  char buffer[64 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"cosmos-sdk/MsgWithdrawDelegationReward\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":{\"amount\":\"%" PRIu64
                                 "\",\"denom\":\"%s\"},",
                                 rewardsmsg->amount, rewardsmsg->denom);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"delegator_address\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 rewardsmsg->delegator_address);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 rewardsmsg->validator_address);

  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgSwap(const OsmosisMsgSwap *swapmsg) {
  char buffer[64 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"osmosis/gamm/swap-exact-amount-in\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"routes\":[{");
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"poolId\":%s\",", swapmsg->pool_id);
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"tokenOutDenom\":%s\"}],",
                                 swapmsg->token_out_denom);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"sender\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 swapmsg->sender);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"tokenIn\":{");
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":%" PRIu64 "\",",
                                 swapmsg->token_in_amount);
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"denom\":\"%s\"},", swapmsg->token_in_denom);
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"tokenOutMinAmount\":\"%" PRIu64 "\"}}",
                                 swapmsg->token_out_min_amount);

  msgs_remaining--;
  return success;
}

// bool osmosis_signTxUpdateMsgIBCDeposit(
//     const OsmosisMsgIBCDeposit *ibcdepositmsg) {
//   char buffer[64 + 1];

//   bool success = true;

//   const char *const prelude =
//       "{\"type\":\"cosmos-sdk/MsgTransfer\",\"value\":{";
//   sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
//   "\"receiver\":"); success &= tendermint_snprintf(&ctx, buffer,
//   sizeof(buffer), "\"%s\",",
//                                  ibcdepositmsg->receiver);

//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
//   "\"sender\":"); success &= tendermint_snprintf(&ctx, buffer,
//   sizeof(buffer), "\"%s\",",
//                                  ibcdepositmsg->sender);

//   success &=
//       tendermint_snprintf(&ctx, buffer, sizeof(buffer),
//       "\"source_channel\":");
//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
//                                  ibcdepositmsg->source_channel);

//   success &=
//       tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"source_port\":");
//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
//                                  ibcdepositmsg->source_port);

//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
//                                  "\"timeout_height\":{\"revision_height\":");
//   success &=
//       tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%" PRIu64 "\",",
//                           ibcdepositmsg->timeout_height.revision_height);

//   success &=
//       tendermint_snprintf(&ctx, buffer, sizeof(buffer),
//       "\"revision_number\":");
//   success &=
//       tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%" PRIu64 "\"},",
//                           ibcdepositmsg->timeout_height.revision_number);

//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
//                                  "\"token\":{\"amount\":");
//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
//                                  ibcdepositmsg->token.amount);
//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"denom\":");
//   success &=
//       tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%" PRIu64 "\"}}}",
//                           ibcdepositmsg->token.denom);

//   msgs_remaining--;
//   return success;
// }

// bool osmosis_signTxUpdateMsgIBCWithdrawal(
//     const OsmosisMsgIBCWithdrawal *ibcwithdrawalmsg) {
//   char buffer[64 + 1];

//   bool success = true;

//   const char *const prelude =
//       "{\"type\":\"cosmos-sdk/MsgTransfer\",\"value\":{";
//   sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
//   "\"receiver\":"); success &= tendermint_snprintf(&ctx, buffer,
//   sizeof(buffer), "\"%s\",",
//                                  ibcwithdrawalmsg->receiver);

//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
//   "\"sender\":"); success &= tendermint_snprintf(&ctx, buffer,
//   sizeof(buffer), "\"%s\",",
//                                  ibcwithdrawalmsg->sender);

//   success &=
//       tendermint_snprintf(&ctx, buffer, sizeof(buffer),
//       "\"source_channel\":");
//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
//                                  ibcwithdrawalmsg->source_channel);

//   success &=
//       tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"source_port\":");
//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
//                                  ibcwithdrawalmsg->source_port);

//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
//                                  "\"timeout_height\":{\"revision_height\":");
//   success &=
//       tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%" PRIu64 "\",",
//                           ibcwithdrawalmsg->timeout_height.revision_height);

//   success &=
//       tendermint_snprintf(&ctx, buffer, sizeof(buffer),
//       "\"revision_number\":");
//   success &=
//       tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%" PRIu64 "\"},",
//                           ibcwithdrawalmsg->timeout_height.revision_number);

//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
//                                  "\"token\":{\"amount\":");
//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
//                                  ibcwithdrawalmsg->amount);
//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"denom\":");
//   success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
//                                  "\"%" PRIu64 "\"}}}",
//                                  ibcwithdrawalmsg->denom);
//   msgs_remaining--;
//   return success;
// }

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

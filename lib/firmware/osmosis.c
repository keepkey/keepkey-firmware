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
static bool has_message;
static uint32_t msgs_remaining;
static OsmosisSignTx msg;
static bool testnet;

const OsmosisSignTx* osmosis_getOsmosisSignTx(void) { return &msg; }

bool osmosis_validate_required_text(bool has_value, const char* value) {
  return has_value && tendermint_validateSafeText(value);
}

bool osmosis_validate_amount(bool has_value, const char* value) {
  if (!osmosis_validate_required_text(has_value, value)) return false;
  for (const char* p = value; *p; ++p) {
    if (*p < '0' || *p > '9') return false;
  }
  return true;
}

bool osmosis_signTxInit(const HDNode* _node, const OsmosisSignTx* _msg) {
  osmosis_signAbort();
  if (!_node || !_msg || !_msg->has_msg_count || _msg->msg_count == 0 ||
      !_msg->has_chain_id || !tendermint_validateSafeText(_msg->chain_id)) {
    return false;
  }

  msgs_remaining = _msg->msg_count;
  testnet = false;

  if (_msg->has_testnet) {
    testnet = _msg->testnet;
  }

  memzero(&node, sizeof(node));
  memcpy(&node, _node, sizeof(node));
  memcpy(&msg, _msg, sizeof(msg));

  bool success = true;
  char buffer[64 + 1] = {0};

  sha256_Init(&ctx);

  // Each segment guaranteed to be less than or equal to 64 bytes
  // 19 + ^20 + 1 = ^40
  if (!tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                           "{\"account_number\":\"%" PRIu64 "\"",
                           msg.account_number))
    return false;

  // <escape chain_id>
  const char* const chainid_prefix = ",\"chain_id\":\"";
  sha256_Update(&ctx, (uint8_t*)chainid_prefix, strlen(chainid_prefix));

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
  const char* const memo_prefix = ",\"memo\":\"";
  sha256_Update(&ctx, (uint8_t*)memo_prefix, strlen(memo_prefix));

  if (msg.has_memo) {
    tendermint_sha256UpdateEscaped(&ctx, msg.memo, strlen(msg.memo));
  }

  // 10
  sha256_Update(&ctx, (uint8_t*)"\",\"msgs\":[", 10);

  if (!success) {
    osmosis_signAbort();
    return false;
  }
  initialized = true;
  return true;
}

bool osmosis_signTxUpdateMsgSend(const char* amount, const char* to_address,
                                 const char* denom) {
  if (!initialized || msgs_remaining == 0) return false;

  const char mainnetp[] = "osmo";
  const char testnetp[] = "tosmo";
  const char* pfix;
  char buffer[64 + 1];

  size_t decoded_len;
  char hrp[45] = {0};
  uint8_t decoded[38] = {0};
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
    sha256_Update(&ctx, (uint8_t*)",", 1);
  }

  bool success = true;

  const char* const prelude = "{\"type\":\"cosmos-sdk/MsgSend\",\"value\":{";
  sha256_Update(&ctx, (uint8_t*)prelude, strlen(prelude));

  // The amount and denom are host-supplied and land in the signed document
  // verbatim, so escape them the way chain_id and memo are escaped in
  // osmosis_signTxInit. Hashing in segments also lifts the 64-byte scratch
  // buffer limit, which IBC and factory denom paths exceed.
  const char* const amount_prefix = "\"amount\":[{\"amount\":\"";
  sha256_Update(&ctx, (uint8_t*)amount_prefix, strlen(amount_prefix));
  tendermint_sha256UpdateEscaped(&ctx, amount, strlen(amount));

  const char* const denom_prefix = "\",\"denom\":\"";
  sha256_Update(&ctx, (uint8_t*)denom_prefix, strlen(denom_prefix));
  tendermint_sha256UpdateEscaped(&ctx, denom, strlen(denom));

  const char* const coin_suffix = "\"}]";
  sha256_Update(&ctx, (uint8_t*)coin_suffix, strlen(coin_suffix));

  // 17 + 45 + 1 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"from_address\":\"%s\"", from_address);

  // 15 + 45 + 3 = 63
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 ",\"to_address\":\"%s\"}}", to_address);

  if (success) {
    has_message = true;
  }
  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgDelegate(const char* amount,
                                     const char* delegator_address,
                                     const char* validator_address,
                                     const char* denom) {
  if (!initialized || msgs_remaining == 0) return false;

  const char mainnetp[] = "osmo";
  const char testnetp[] = "tosmo";
  const char* pfix;

  char buffer[128] = {0};
  size_t decoded_len;
  char hrp[45] = {0};
  uint8_t decoded[38] = {0};

  if (!bech32_decode(hrp, decoded, &decoded_len, delegator_address)) {
    return false;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54] = {0};

  pfix = mainnetp;
  if (testnet) {
    pfix = testnetp;
  }

  if (!tendermint_getAddress(&node, pfix, from_address)) {
    return false;
  }

  if (has_message) {
    sha256_Update(&ctx, (uint8_t*)",", 1);
  }

  bool success = true;

  // 9 + ^24 + 23 = ^56
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "{\"type\":\"cosmos-sdk/MsgDelegate\",\"value\":{");

  // 20 + ^20 + 11 + ^9 + 2 = ^62
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "\"amount\":{\"amount\":\"%s\",\"denom\":\"%s\"}", amount, denom);

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

  if (success) {
    has_message = true;
  }
  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgUndelegate(const char* amount,
                                       const char* delegator_address,
                                       const char* validator_address,
                                       const char* denom) {
  if (!initialized || msgs_remaining == 0) return false;

  const char mainnetp[] = "osmo";
  const char testnetp[] = "tosmo";
  const char* pfix;

  char buffer[128] = {0};
  size_t decoded_len;
  char hrp[45] = {0};
  uint8_t decoded[38] = {0};

  if (!bech32_decode(hrp, decoded, &decoded_len, delegator_address)) {
    return false;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54] = {0};

  pfix = mainnetp;
  if (testnet) {
    pfix = testnetp;
  }
  if (!tendermint_getAddress(&node, pfix, from_address)) {
    return false;
  }

  if (has_message) {
    sha256_Update(&ctx, (uint8_t*)",", 1);
  }

  bool success = true;

  // 9 + ^24 + 25 = ^58
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "{\"type\":\"cosmos-sdk/MsgUndelegate\",\"value\":{");

  // 20 + ^20 + 11 + ^9 + 2 = ^62
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "\"amount\":{\"amount\":\"%s\",\"denom\":\"%s\"}", amount, denom);

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

  if (success) {
    has_message = true;
  }
  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgRedelegate(const char* amount,
                                       const char* delegator_address,
                                       const char* validator_src_address,
                                       const char* validator_dst_address,
                                       const char* denom) {
  if (!initialized || msgs_remaining == 0) return false;

  const char mainnetp[] = "osmo";
  const char testnetp[] = "tosmo";
  const char* pfix;

  char buffer[128] = {0};
  size_t decoded_len;
  char hrp[45] = {0};
  uint8_t decoded[38] = {0};

  if (!bech32_decode(hrp, decoded, &decoded_len, delegator_address)) {
    return false;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54] = {0};
  pfix = mainnetp;
  if (testnet) {
    pfix = testnetp;
  }
  if (!tendermint_getAddress(&node, pfix, from_address)) {
    return false;
  }

  if (has_message) {
    sha256_Update(&ctx, (uint8_t*)",", 1);
  }

  bool success = true;

  // 9 + ^24 + 28 = ^64
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "{\"type\":\"cosmos-sdk/MsgBeginRedelegate\",\"value\"");

  // 22 + ^20 + 11 + ^9 + 2 = ^64
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      ":{\"amount\":{\"amount\":\"%s\",\"denom\":\"%s\"}", amount, denom);

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

  if (success) {
    has_message = true;
  }
  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgLPAdd(const uint64_t pool_id, const char* sender,
                                  const char* share_out_amount,
                                  const char* amount_in_max_a,
                                  const char* denom_in_max_a,
                                  const char* amount_in_max_b,
                                  const char* denom_in_max_b) {
  if (!initialized || msgs_remaining == 0) return false;

  char buffer[96 + 1] = {0};

  if (has_message) {
    sha256_Update(&ctx, (uint8_t*)",", 1);
  }

  bool success = true;

  const char* const prelude =
      "{\"type\":\"osmosis/gamm/join-pool\",\"value\":{";
  sha256_Update(&ctx, (uint8_t*)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"pool_id\":\"%" PRIu64 "\",", pool_id);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"sender\":");

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",", sender);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"share_out_amount\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 share_out_amount);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"token_in_maxs\":[{");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":\"%s\",", amount_in_max_a);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"denom\":\"%s\"},", denom_in_max_a);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "{\"amount\":\"%s\",", amount_in_max_b);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"denom\":\"%s\"}]}}", denom_in_max_b);

  if (success) {
    has_message = true;
  }
  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgLPRemove(const uint64_t pool_id, const char* sender,
                                     const char* share_out_amount,
                                     const char* amount_out_min_a,
                                     const char* denom_out_min_a,
                                     const char* amount_out_min_b,
                                     const char* denom_out_min_b) {
  if (!initialized || msgs_remaining == 0) return false;

  char buffer[96 + 1] = {0};

  if (has_message) {
    sha256_Update(&ctx, (uint8_t*)",", 1);
  }

  bool success = true;

  const char* const prelude =
      "{\"type\":\"osmosis/gamm/exit-pool\",\"value\":{";
  sha256_Update(&ctx, (uint8_t*)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"pool_id\":\"%" PRIu64 "\",", pool_id);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"sender\":");

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",", sender);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"share_in_amount\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 share_out_amount);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"token_out_mins\":[{");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"amount\":\"%s\",", amount_out_min_a);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"denom\":\"%s\"},", denom_out_min_a);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "{\"amount\":\"%s\",", amount_out_min_b);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"denom\":\"%s\"}]}}", denom_out_min_b);

  if (success) {
    has_message = true;
  }
  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgRewards(const char* delegator_address,
                                    const char* validator_address) {
  if (!initialized || msgs_remaining == 0) return false;

  const char mainnetp[] = "osmo";
  const char testnetp[] = "tosmo";
  const char* pfix;

  char buffer[128] = {0};
  size_t decoded_len;
  char hrp[45] = {0};
  uint8_t decoded[38] = {0};

  if (!bech32_decode(hrp, decoded, &decoded_len, delegator_address)) {
    return false;
  }

  pfix = mainnetp;
  if (testnet) {
    pfix = testnetp;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54] = {0};
  if (!tendermint_getAddress(&node, pfix, from_address)) {
    return false;
  }

  if (has_message) {
    sha256_Update(&ctx, (uint8_t*)",", 1);
  }

  bool success = true;

  // 9 + ^24 + 38 = ^72
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "{\"type\":\"cosmos-sdk/MsgWithdrawDelegationReward\",\"value\":{");

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

  if (success) {
    has_message = true;
  }
  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgIBCTransfer(const char* amount, const char* sender,
                                        const char* receiver,
                                        const char* source_channel,
                                        const char* source_port,
                                        const char* revision_number,
                                        const char* revision_height,
                                        const char* denom) {
  if (!initialized || msgs_remaining == 0) return false;

  const char mainnetp[] = "osmo";
  const char testnetp[] = "tosmo";
  const char* pfix;

  char buffer[128] = {0};
  size_t decoded_len;
  char hrp[45] = {0};
  uint8_t decoded[38] = {0};

  if (!bech32_decode(hrp, decoded, &decoded_len, receiver)) {
    return false;
  }

  pfix = mainnetp;
  if (testnet) {
    pfix = testnetp;
  }

  // ^14 + 39 + 1 = ^54
  char from_address[54] = {0};
  if (!tendermint_getAddress(&node, pfix, from_address)) {
    return false;
  }

  if (has_message) {
    sha256_Update(&ctx, (uint8_t*)",", 1);
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
  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "\"token\":{\"amount\":\"%s\",\"denom\":\"%s\"}}}", amount, denom);

  if (success) {
    has_message = true;
  }
  msgs_remaining--;
  return success;
}

bool osmosis_signTxUpdateMsgSwap(const uint64_t pool_id,
                                 const char* token_out_denom,
                                 const char* sender,
                                 const char* token_in_amount,
                                 const char* token_in_denom,
                                 const char* token_out_min_amount) {
  if (!initialized || msgs_remaining == 0) return false;

  char buffer[96 + 1] = {0};

  // TODO: add testnet support

  if (has_message) {
    sha256_Update(&ctx, (uint8_t*)",", 1);
  }

  bool success = true;

  const char* const prelude =
      "{\"type\":\"osmosis/gamm/swap-exact-amount-in\",";
  sha256_Update(&ctx, (uint8_t*)prelude, strlen(prelude));

  success &= tendermint_snprintf(
      &ctx, buffer, sizeof(buffer),
      "\"value\":{\"routes\":[{\"pool_id\":\"%" PRIu64 "\",", pool_id);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "\"token_out_denom\":\"%s\"}],", token_out_denom);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"sender\":\"%s\",", sender);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "\"token_in\":{\"amount\":\"%s\",", token_in_amount);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"denom\":\"%s\"},", token_in_denom);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"token_out_min_amount\":\"%s\"}}",
                                 token_out_min_amount);

  if (success) {
    has_message = true;
  }
  msgs_remaining--;
  return success;
}

bool osmosis_signTxFinalize(uint8_t* public_key, uint8_t* signature) {
  char buffer[128] = {0};

  // 14 + ^20 + 2 = ^36
  if (!tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                           "],\"sequence\":\"%" PRIu64 "\"}", msg.sequence)) {
    return false;
  }

  hdnode_fill_public_key(&node);
  memcpy(public_key, node.public_key, 33);

  uint8_t hash[SHA256_DIGEST_LENGTH];
  sha256_Final(&ctx, hash);
  return ecdsa_sign_digest(&secp256k1, node.private_key, hash, signature, NULL,
                           NULL) == 0;
}

bool osmosis_signingIsInited(void) { return initialized; }

bool osmosis_signingIsFinished(void) {
  return msgs_remaining == 0 && has_message;
}

void osmosis_signAbort(void) {
  initialized = false;
  has_message = false;
  msgs_remaining = 0;
  memzero(&msg, sizeof(msg));
  memzero(&node, sizeof(node));
}

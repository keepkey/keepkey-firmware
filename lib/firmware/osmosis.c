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

static SHA256_CTX ctx;
static uint32_t msgs_remaining;
static OsmosisSignTx msg;

const OsmosisSignTx *osmosis_getOsmosisSignTx(void) { return &msg; }

bool osmosis_signTxUpdateMsgLPAdd(const OsmosisMsgLPAdd msglpadd) {
  char buffer[64 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"osmosis/gamm/join-pool\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"poolId\":\"%s\",", msglpadd.pool_id);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"sender\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 msglpadd.sender);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"shareOutAmount\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"%" PRIu64 "\",", msglpadd.share_out_amount);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"tokenInMaxs\":[{");

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
  char buffer[64 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"osmosis/gamm/exit-pool\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"poolId\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 msglpremove.pool_id);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"sender\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 msglpremove.sender);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"shareOutAmount\":");

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%" PRIu64 "\",",
                          msglpremove.share_out_amount);

  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"tokenOutMins\":[{");

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
  char buffer[64 + 1];

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
  char buffer[64 + 1];

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
  char buffer[64 + 1];

  bool success = true;

  const char *const prelude =
      "{\"type\":\"osmosis/gamm/swap-exact-amount-in\",\"value\":{";
  sha256_Update(&ctx, (uint8_t *)prelude, strlen(prelude));

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"routes\":[{");
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"poolId\":%s\",", msgswap.pool_id);
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "\"tokenOutDenom\":%s\"}],", msgswap.token_out_denom);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"sender\":");

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"%s\",",
                                 msgswap.sender);

  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer), "\"tokenIn\":{");
  success &=
      tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                          "\"amount\":%" PRIu64 "\",", msgswap.token_in_amount);
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"denom\":\"%s\"},", msgswap.token_in_denom);
  success &= tendermint_snprintf(&ctx, buffer, sizeof(buffer),
                                 "\"tokenOutMinAmount\":\"%" PRIu64 "\"}}",
                                 msgswap.token_out_min_amount);

  msgs_remaining--;
  return success;
}

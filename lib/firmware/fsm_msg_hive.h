/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
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

void fsm_msgHiveGetPublicKey(const HiveGetPublicKey* msg) {
  RESP_INIT(HivePublicKey);

  CHECK_INITIALIZED
  CHECK_PIN

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  // Return raw 33-byte compressed pubkey
  resp->has_raw_public_key = true;
  resp->raw_public_key.size = 33;
  memcpy(resp->raw_public_key.bytes, node->public_key, 33);

  // Return STM-encoded public key
  resp->has_public_key = true;
  if (!hive_getPublicKey(node->public_key, resp->public_key,
                         sizeof(resp->public_key))) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to encode Hive public key"));
    layoutHome();
    return;
  }

  if (msg->has_show_display && msg->show_display) {
    if (!confirm_ethereum_address("Hive Public Key", resp->public_key)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Show public key cancelled"));
      layoutHome();
      return;
    }
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_HivePublicKey, resp);
  layoutHome();
}

void fsm_msgHiveSignTx(const HiveSignTx* msg) {
  RESP_INIT(HiveSignedTx);

  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_from || !msg->has_to || !msg->has_amount ||
      !msg->has_ref_block_num || !msg->has_ref_block_prefix ||
      !msg->has_expiration) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Missing required Hive transaction fields"));
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  // Format amount string for confirmation
  const char* symbol = msg->has_asset_symbol ? msg->asset_symbol : "HIVE";
  uint32_t decimals = msg->has_decimals ? msg->decimals : HIVE_DECIMALS;

  char amount_str[32];
  uint64_t whole = msg->amount / 1000;
  uint64_t frac = msg->amount % 1000;
  // Simple format: decimals=3 → "X.XXX SYMBOL"
  (void)decimals;
  snprintf(amount_str, sizeof(amount_str), "%" PRIu64 ".%03" PRIu64 " %s",
           whole, frac, symbol);

  if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Send Hive",
               "Send %s to @%s?", amount_str, msg->to)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (msg->has_memo && strlen(msg->memo) > 0) {
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmMemo, "Memo", "%s",
                 msg->memo)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Sign Transaction",
               "Sign Hive transaction from @%s?", msg->from)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  hive_signTx(node, msg, resp);
  memzero(node, sizeof(*node));

  if (!resp->has_signature) {
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Hive signing failed"));
    layoutHome();
    return;
  }

  msg_write(MessageType_MessageType_HiveSignedTx, resp);
  layoutHome();
}

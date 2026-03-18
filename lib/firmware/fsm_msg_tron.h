/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2024 KeepKey
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

#include "tron_tokens.h"

void fsm_msgTronGetAddress(const TronGetAddress *msg) {
  RESP_INIT(TronAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate path: m/44'/195'/...
  if (msg->address_n_count < 3 ||
      msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 195)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TRON path (expected m/44'/195'/...)"));
    layoutHome();
    return;
  }

  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  char address[MAX_ADDR_SIZE];
  if (!tron_getAddress(node->public_key, address, sizeof(address))) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("Address derivation failed"));
    layoutHome();
    return;
  }

  resp->has_address = true;
  strlcpy(resp->address, address, sizeof(resp->address));

  if (msg->has_show_display && msg->show_display) {
    char node_str[NODE_STRING_LENGTH];
    if (!bip32_path_to_string(node_str, sizeof(node_str), msg->address_n,
                              msg->address_n_count)) {
      memset(node_str, 0, sizeof(node_str));
    }

    if (!confirm_ethereum_address(node_str, resp->address)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Show address cancelled"));
      layoutHome();
      return;
    }
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_TronAddress, resp);
  layoutHome();
}

void fsm_msgTronSignTx(TronSignTx *msg) {
  RESP_INIT(TronSignedTx);

  CHECK_INITIALIZED

  CHECK_PIN

  // Validate path: m/44'/195'/...
  if (msg->address_n_count < 3 ||
      msg->address_n[0] != (0x80000000 | 44) ||
      msg->address_n[1] != (0x80000000 | 195)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid TRON path (expected m/44'/195'/...)"));
    layoutHome();
    return;
  }

  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  hdnode_fill_public_key(node);

  bool is_structured = msg->has_transfer || msg->has_trigger_smart;
  bool is_legacy = msg->has_raw_data && msg->raw_data.size > 0;

  if (!is_structured && !is_legacy) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Must provide transfer, trigger_smart, or raw_data"));
    layoutHome();
    return;
  }

  /* Reject if both contract types are present — exactly one required */
  if (msg->has_transfer && msg->has_trigger_smart) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Cannot set both transfer and trigger_smart"));
    layoutHome();
    return;
  }

  /* ---- Structured reconstruct-then-sign path ---- */
  if (is_structured) {
    /* Validate required header fields */
    if (!msg->has_ref_block_bytes || msg->ref_block_bytes.size != 2) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("ref_block_bytes must be exactly 2 bytes"));
      layoutHome();
      return;
    }
    if (!msg->has_ref_block_hash || msg->ref_block_hash.size != 8) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("ref_block_hash must be exactly 8 bytes"));
      layoutHome();
      return;
    }
    if (!msg->has_expiration) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("expiration is required"));
      layoutHome();
      return;
    }

    /* Show memo if present */
    if (msg->has_data && msg->data.size > 0) {
      char memo_hex[65];
      size_t show = msg->data.size < 32 ? msg->data.size : 32;
      for (size_t i = 0; i < show; i++) {
        snprintf(memo_hex + i * 2, 3, "%02x", msg->data.bytes[i]);
      }
      if (msg->data.size > 32) {
        strlcat(memo_hex, "...", sizeof(memo_hex));
      }
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Memo", "Transaction memo:\n%s", memo_hex)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
      }
    }

    /* ---- TransferContract path ---- */
    if (msg->has_transfer) {
      /* Validate to_address BEFORE display */
      if (!tron_validateAddress(msg->transfer.to_address)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Invalid to_address in transfer"));
        layoutHome();
        return;
      }

      char amount_str[64];
      tron_formatAmount(amount_str, sizeof(amount_str), msg->transfer.amount);

      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Send TRX", "Send %s to\n%s?",
                   amount_str, msg->transfer.to_address)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
      }
    }

    /* ---- TriggerSmartContract path ---- */
    if (msg->has_trigger_smart) {
      /* Validate contract_address BEFORE any display */
      if (!tron_validateAddress(msg->trigger_smart.contract_address)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        _("Invalid contract_address"));
        layoutHome();
        return;
      }

      /* Attempt TRC-20 transfer(address,uint256) decode */
      uint8_t trc20_to[TRON_ADDRESS_SIZE];
      uint8_t trc20_amount[32];
      bool is_trc20 = msg->trigger_smart.has_data &&
                      msg->trigger_smart.data.size >= 68 &&
                      tron_decodeTRC20Transfer(msg->trigger_smart.data.bytes,
                                               msg->trigger_smart.data.size,
                                               trc20_to, trc20_amount);

      if (is_trc20) {
        /* Look up known token by contract address */
        const TronToken *token =
            tron_token_by_address(msg->trigger_smart.contract_address);

        char to_addr[MAX_TRON_ADDR_SIZE];
        if (!base58_encode_check(trc20_to, 21, HASHER_SHA2D, to_addr,
                                 sizeof(to_addr))) {
          memzero(node, sizeof(*node));
          fsm_sendFailure(FailureType_Failure_Other,
                          _("Failed to encode recipient address"));
          layoutHome();
          return;
        }

        if (token) {
          char amt_str[64];
          tron_formatTokenAmount(amt_str, sizeof(amt_str), trc20_amount,
                                 token->decimals, token->symbol);
          if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                       "Send Token", "Send %s to\n%s?",
                       amt_str, to_addr)) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            _("Signing cancelled"));
            layoutHome();
            return;
          }
        } else {
          /* Unknown TRC-20 token */
          if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                       "Unknown Token",
                       "Transfer unknown token at\n%s\nto %s?",
                       msg->trigger_smart.contract_address, to_addr)) {
            memzero(node, sizeof(*node));
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            _("Signing cancelled"));
            layoutHome();
            return;
          }
        }
      } else {
        /* Not a TRC-20 transfer — generic smart contract call */
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                     "Contract Call",
                     "Call contract\n%s?\nCannot verify call data.",
                     msg->trigger_smart.contract_address)) {
          memzero(node, sizeof(*node));
          fsm_sendFailure(FailureType_Failure_ActionCancelled,
                          _("Signing cancelled"));
          layoutHome();
          return;
        }
      }

      /* Show call_value if sending TRX along with the smart contract call */
      if (msg->trigger_smart.has_call_value &&
          msg->trigger_smart.call_value > 0) {
        char call_str[64];
        tron_formatAmount(call_str, sizeof(call_str),
                          msg->trigger_smart.call_value);
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                     "Call Value",
                     "Also sending %s with call?", call_str)) {
          memzero(node, sizeof(*node));
          fsm_sendFailure(FailureType_Failure_ActionCancelled,
                          _("Signing cancelled"));
          layoutHome();
          return;
        }
      }
    }

    /* Show fee limit if present */
    if (msg->has_fee_limit && msg->fee_limit > 0) {
      char fee_str[64];
      tron_formatAmount(fee_str, sizeof(fee_str), msg->fee_limit);
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Fee Limit", "Maximum fee:\n%s?", fee_str)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
      }
    }

    /* Final confirmation */
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Sign",
                 "Sign this TRON transaction?")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }
  }

  /* ---- Legacy blind-sign path ---- */
  if (!is_structured) {
    /* Blind-sign warning: user must understand this is unverified */
    if (!confirm(ButtonRequestType_ButtonRequest_SignTx,
                 "Blind Sign",
                 "Sign unverified TRON\ntransaction?\n"
                 "Data cannot be verified\non-device.")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Signing cancelled"));
      layoutHome();
      return;
    }

    /* Show optional unverified hints from host */
    if (msg->has_to_address && msg->has_amount) {
      char amount_str[64];
      tron_formatAmount(amount_str, sizeof(amount_str), msg->amount);
      if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput,
                   "Unverified", "Send %s to\n%s?\n(UNVERIFIED)",
                   amount_str, msg->to_address)) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled"));
        layoutHome();
        return;
      }
    }
  }

  /* Sign the transaction */
  if (!tron_signTx(node, msg, resp)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_Other, _("TRON signing failed"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_TronSignedTx, resp);
  layoutHome();
}

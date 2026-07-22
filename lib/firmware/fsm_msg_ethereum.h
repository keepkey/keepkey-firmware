
/*
 * This file is part of the Keepkey project
 *
 * Copyright (C) 2022 markrypto
 * Copyright (C) 2018 keepkey
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

#include "keepkey/firmware/signed_metadata.h"

void fsm_msgEthereumTxMetadata(const EthereumTxMetadata* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  /* Metadata must arrive before signing starts. signed_metadata_process()
   * clears the binding on entry, so accepting metadata mid-signing would
   * drop the tx<->metadata binding without aborting: a host could approve a
   * benign decode (suppressing the blind-sign gate), then inject metadata to
   * clear the binding and stream attacker-chosen calldata for the rest.
   * Refuse and abort any in-progress signing session. */
  if (ethereum_signing_isInProgress()) {
    ethereum_signing_abort();
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Metadata not allowed during signing"));
    layoutHome();
    return;
  }

  RESP_INIT(EthereumMetadataAck);

  MetadataClassification result = signed_metadata_process(
      msg->signed_payload.bytes, msg->signed_payload.size,
      msg->has_key_id ? msg->key_id : 0);

  resp->classification = (uint32_t)result;
  resp->has_display_summary = true;

  switch (result) {
    case METADATA_VERIFIED:
      strlcpy(resp->display_summary, "Verified", sizeof(resp->display_summary));
      break;
    case METADATA_OPAQUE:
      strlcpy(resp->display_summary, "Unverified",
              sizeof(resp->display_summary));
      break;
    case METADATA_MALFORMED:
    default:
      strlcpy(resp->display_summary, "Invalid", sizeof(resp->display_summary));
      break;
  }

  msg_write(MessageType_MessageType_EthereumMetadataAck, resp);
}

void fsm_msgLoadClearsignSigner(const LoadClearsignSigner* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  CHECK_PARAM(msg->has_key_id && msg->has_pubkey && msg->has_alias,
              _("key_id, pubkey and alias required"));
  /* Range-check as uint32 BEFORE narrowing: (uint8_t)256 would alias slot 0 */
  CHECK_PARAM(msg->key_id < METADATA_MAX_KEYS, _("key_id out of range"));
  CHECK_PARAM(
      signed_metadata_signer_valid((uint8_t)msg->key_id, msg->pubkey.bytes,
                                   msg->pubkey.size, msg->alias),
      _("Invalid clearsign signer"));

  /* Optional identity icon (1bpp mono RLE). The proto caps icon at 384 bytes;
   * bound the dims too so the render path never scans a bogus geometry. An icon
   * with zero/oversized dims is rejected rather than silently dropped so a
   * malformed upload is visible, not a mystery text-only identity. */
  const uint8_t* icon = NULL;
  uint16_t icon_len = 0;
  uint8_t icon_w = 0, icon_h = 0;
  if (msg->has_icon && msg->icon.size > 0) {
    CHECK_PARAM(msg->icon.size <= METADATA_ICON_MAX, _("icon too large"));
    /* Width is capped at the confirm screen's icon column
     * (LEFT_MARGIN_WITH_ICON = 40), NOT at the 64px height. Title/body text
     * begins at x=40 and the icon is drawn AFTER the text, so a wider
     * host-supplied icon would paint over the alias, fingerprint and the
     * "NOT verified by KeepKey" warning — on the very screen that exists to
     * carry that warning. This is the trust boundary for icons arriving on the
     * wire; icons READ BACK from flash are re-checked independently in
     * signed_metadata_signer_icon(), since a record persisted by older firmware
     * never passes through here again after a reboot. */
    CHECK_PARAM(msg->has_icon_width && msg->has_icon_height &&
                    msg->icon_width > 0 &&
                    msg->icon_width <= LEFT_MARGIN_WITH_ICON &&
                    msg->icon_height > 0 && msg->icon_height <= 64,
                _("icon dimensions out of range"));
    /* Reject a malformed RLE stream HERE rather than discovering it at draw
     * time. The render path returns a bool that layout_add_icon() discards, so
     * an undecodable icon would otherwise show no logo, still return Success,
     * and be persisted to flash — the user consents to an identity whose logo
     * silently does not exist. Validation is exact (every packet well-formed,
     * no run straddling the image, whole input consumed) and side-effect-free.
     */
    CHECK_PARAM(draw_bitmap_mono_rle_valid(
                    msg->icon.bytes, (uint32_t)msg->icon.size,
                    (uint16_t)msg->icon_width, (uint16_t)msg->icon_height),
                _("invalid icon encoding"));
    icon = msg->icon.bytes;
    icon_len = (uint16_t)msg->icon.size;
    icon_w = (uint8_t)msg->icon_width;
    icon_h = (uint8_t)msg->icon_height;
  }
  bool persist = msg->has_persist && msg->persist;

  /* Mandatory on-device consent — leads with the identity's logo (if any) +
   * alias + fingerprint. The whole trust model hangs on this confirm; the same
   * fingerprint reappears on every per-tx identity screen. persist makes the
   * trust anchor durable across reboots, so it's called out. */
  char fingerprint[METADATA_FINGERPRINT_LEN];
  signed_metadata_pubkey_fingerprint(msg->pubkey.bytes, fingerprint);
  if (!signed_metadata_confirm_load(msg->alias, fingerprint, icon, icon_w,
                                    icon_h, icon_len, persist)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Load clearsign signer cancelled"));
    layoutHome();
    return;
  }

  if (!signed_metadata_store_signer((uint8_t)msg->key_id, msg->pubkey.bytes,
                                    msg->alias, icon, icon_w, icon_h, icon_len,
                                    persist)) {
    /* Session signer stored, but no persistent slot was free. Tell the truth
     * rather than silently keeping it RAM-only under a persist request. */
    fsm_sendFailure(FailureType_Failure_Other,
                    _("No free persistent identity slot — wipe an old one"));
    layoutHome();
    return;
  }
  fsm_sendSuccess(_("Clearsign signer loaded"));
  layoutHome();
}

static int process_ethereum_xfer(const CoinType* coin, EthereumSignTx* msg) {
  if (!ethereum_isStandardERC20Transfer(msg) && msg->data_length != 0)
    return TXOUT_COMPILE_ERROR;

  char node_str[NODE_STRING_LENGTH];
  if (!bip32_node_to_string(node_str, sizeof(node_str), coin, msg->to_address_n,
                            msg->to_address_n_count, /*whole_account=*/false,
                            /*show_addridx=*/false))
    return TXOUT_COMPILE_ERROR;

  if (!coin->has_forkid) return TXOUT_COMPILE_ERROR;

  const uint32_t chain_id = coin->forkid;

  const uint8_t* value_bytes;
  size_t value_size;
  const TokenType* token;

  if (ethereum_isStandardERC20Transfer(msg)) {
    value_bytes = msg->data_initial_chunk.bytes + 4 + 32;
    value_size = 32;
    token = tokenByChainAddress(chain_id, msg->to.bytes);
  } else {
    value_bytes = msg->value.bytes;
    value_size = msg->value.size;
    token = NULL;
  }

  bignum256 value;
  bn_from_bytes(value_bytes, value_size, &value);

  char amount_str[128 + sizeof(msg->token_shortcut) + 3];
  ethereumFormatAmount(&value, token, chain_id, amount_str, sizeof(amount_str));

  if (!confirm_transfer_output(
          ButtonRequestType_ButtonRequest_ConfirmTransferToAccount, amount_str,
          node_str))
    return TXOUT_CANCEL;

  const HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->to_address_n,
                                          msg->to_address_n_count, NULL);
  if (!node) return TXOUT_COMPILE_ERROR;

  uint8_t to_bytes[20];
  if (!hdnode_get_ethereum_pubkeyhash(node, to_bytes))
    return TXOUT_COMPILE_ERROR;

  if (ethereum_isStandardERC20Transfer(msg)) {
    if (memcmp(msg->data_initial_chunk.bytes + 4 + (32 - 20), to_bytes, 20) !=
        0)
      return TXOUT_COMPILE_ERROR;
  } else {
    msg->has_to = true;
    msg->to.size = 20;
    memcpy(msg->to.bytes, to_bytes, sizeof(to_bytes));
  }

  memzero((void*)node, sizeof(HDNode));
  return TXOUT_OK;
}

static int process_ethereum_msg(EthereumSignTx* msg, bool* needs_confirm) {
  const CoinType* coin = fsm_getCoin(true, ETHEREUM);
  if (!coin) return TXOUT_COMPILE_ERROR;

  switch (msg->address_type) {
    case OutputAddressType_TRANSFER: {
      // prep transfer type transaction
      *needs_confirm = false;
      return process_ethereum_xfer(coin, msg);
    }
    default:
      return TXOUT_OK;
  }
}

void fsm_msgEthereumSignTx(EthereumSignTx* msg) {
  CHECK_INITIALIZED

  CHECK_PIN

  bool needs_confirm = true;
  int msg_result = process_ethereum_msg(msg, &needs_confirm);

  if (msg_result < TXOUT_OK) {
    ethereum_signing_abort();
    send_fsm_co_error_message(msg_result);
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  ethereum_signing_init(msg, node, needs_confirm);
  memzero(node, sizeof(*node));
}

void fsm_msgEthereumTxAck(EthereumTxAck* msg) { ethereum_signing_txack(msg); }

void fsm_msgEthereumGetAddress(EthereumGetAddress* msg) {
  RESP_INIT(EthereumAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  resp->address.size = 20;

  if (!hdnode_get_ethereum_pubkeyhash(node, resp->address.bytes)) {
    memzero(node, sizeof(*node));
    return;
  }

  const CoinType* coin = NULL;
  bool rskip60 = false;
  uint32_t chain_id = 0;

  if (msg->address_n_count == 5) {
    coin = coinBySlip44(msg->address_n[1]);
    uint32_t slip44 = msg->address_n[1] & 0x7fffffff;
    // constants from trezor-common/defs/ethereum/networks.json
    switch (slip44) {
      case 137:
        rskip60 = true;
        chain_id = 30;
        break;
      case 37310:
        rskip60 = true;
        chain_id = 31;
        break;
    }
  }

  char address[43] = {'0', 'x'};
  ethereum_address_checksum(resp->address.bytes, address + 2, rskip60,
                            chain_id);

  resp->has_address_str = true;
  strlcpy(resp->address_str, address, sizeof(resp->address_str));

  if (msg->has_show_display && msg->show_display) {
    char node_str[NODE_STRING_LENGTH];
    if (!(coin && isEthereumLike(coin->coin_name) &&
          bip32_node_to_string(node_str, sizeof(node_str), coin, msg->address_n,
                               msg->address_n_count,
                               /*whole_account=*/false,
                               /*show_addridx=*/false)) &&
        !bip32_path_to_string(node_str, sizeof(node_str), msg->address_n,
                              msg->address_n_count)) {
      memset(node_str, 0, sizeof(node_str));
    }

    if (!confirm_ethereum_address(node_str, address)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Show address cancelled"));
      layoutHome();
      return;
    }
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_EthereumAddress, resp);
  layoutHome();
}

void fsm_msgEthereumSignMessage(EthereumSignMessage* msg) {
  RESP_INIT(EthereumMessageSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  if (!confirm_bytes(ButtonRequestType_ButtonRequest_ProtectCall,
                     "Sign Ethereum Message", msg->message.bytes,
                     msg->message.size)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  ethereum_message_sign(msg, node, resp);
  memzero(node, sizeof(*node));
  layoutHome();
}

void fsm_msgEthereumVerifyMessage(const EthereumVerifyMessage* msg) {
  CHECK_PARAM(msg->has_address, _("No address provided"));
  CHECK_PARAM(msg->has_message, _("No message provided"));

  if (ethereum_message_verify(msg) != 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Invalid signature"));
    return;
  }

  char address[43] = {'0', 'x'};
  ethereum_address_checksum(msg->address.bytes, address + 2, false, 0);
  if (!confirm_address(_("Confirm Signer"), address)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (!confirm_bytes(ButtonRequestType_ButtonRequest_Other,
                     "Ethereum Message Verified", msg->message.bytes,
                     msg->message.size)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  fsm_sendSuccess(_("Message verified"));

  layoutHome();
}

void fsm_msgEthereumSignTypedHash(const EthereumSignTypedHash* msg) {
  RESP_INIT(EthereumTypedDataSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  /* This endpoint receives only precomputed hashes, so the device cannot bind
   * them to the typed data the host claims they represent. Treat it exactly
   * like every other blind-signing path. */
  if (!ethereum_typed_hash_policy_allows(
          storage_isPolicyEnabled("AdvancedMode"))) {
    (void)review(ButtonRequestType_ButtonRequest_Other, "Blocked",
                 "Typed-hash signing requires AdvancedMode. "
                 "Enable in device settings.");
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Typed-hash signing disabled by policy"));
    layoutHome();
    return;
  }

  if (msg->domain_separator_hash.size != 32 ||
      (msg->has_message_hash && msg->message_hash.size != 32)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid EIP-712 hash length"));
    return;
  }

  const HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                          msg->address_n_count, NULL);
  if (!node) return;

  uint8_t pubkeyhash[20] = {0};
  if (!hdnode_get_ethereum_pubkeyhash(node, pubkeyhash)) {
    layoutHome();
    return;
  }

  resp->address[0] = '0';
  resp->address[1] = 'x';
  ethereum_address_checksum(pubkeyhash, resp->address + 2, false, 0);

  // No message hash when setting primaryType="EIP712Domain"
  // https://ethereum-magicians.org/t/eip-712-standards-clarification-primarytype-as-domaintype/3286
  char str[64 + 1];
  int ctr;

  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Verify Address",
               "Confirm address: %s", resp->address)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  for (ctr = 0; ctr < 64 / 2; ctr++) {
    snprintf(&str[2 * ctr], 3, "%02x", msg->domain_separator_hash.bytes[ctr]);
  }
  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Typed Data domain",
               "Confirm hash digest: %s", str)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (msg->has_message_hash) {
    for (ctr = 0; ctr < 64 / 2; ctr++) {
      snprintf(&str[2 * ctr], 3, "%02x", msg->message_hash.bytes[ctr]);
    }
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Typed Data message",
                 "Confirm hash digest: %s", str)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  } else {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Typed Data message",
                 "Confirm: No message")) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  ethereum_typed_hash_sign(msg, node, resp);
  layoutHome();
}

void fsm_msgEthereum712TypesValues(Ethereum712TypesValues* msg) {
  RESP_INIT(EthereumTypedDataSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  if (strlen(msg->eip712types) == 0) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid EIP-712 types property string"));
    return;
  }

  const HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                          msg->address_n_count, NULL);
  if (!node) return;

  uint8_t pubkeyhash[20] = {0};
  if (!hdnode_get_ethereum_pubkeyhash(node, pubkeyhash)) {
    layoutHome();
    return;
  }

  resp->address[0] = '0';
  resp->address[1] = 'x';
  ethereum_address_checksum(pubkeyhash, resp->address + 2, false, 0);

  e712_types_values(msg, resp, node);

  layoutHome();
}

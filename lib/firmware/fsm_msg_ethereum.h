
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

static int process_ethereum_xfer(const CoinType* coin, EthereumSignTx* msg,
                                 bool* needs_confirm) {
  /* Account routing accepts only a complete canonical ERC20 transfer. Check
   * the declared total too, so streaming a suffix cannot change the signing
   * classifier after the account confirmation has replaced output review. */
  if ((msg->data_length != 0 || msg->data_initial_chunk.size != 0) &&
      (msg->data_length != 68 || !ethereum_isStandardERC20Transfer(msg)))
    return TXOUT_COMPILE_ERROR;

  char node_str[NODE_STRING_LENGTH];
  if (!bip32_node_to_string(node_str, sizeof(node_str), coin, msg->to_address_n,
                            msg->to_address_n_count, /*whole_account=*/false,
                            /*show_addridx=*/false))
    return TXOUT_COMPILE_ERROR;

  char amount_str[128 + sizeof(msg->token_shortcut) + 3];
  const bool amount_is_reviewable =
      ethereumFormatTransferAmount(msg, amount_str, sizeof(amount_str));
  if (!amount_is_reviewable &&
      !(ethereum_isStandardERC20Transfer(msg) &&
        tokenByChainAddress(msg->chain_id, msg->to.bytes) == UnknownToken)) {
    return TXOUT_COMPILE_ERROR;
  }
  if (amount_is_reviewable) {
    if (!confirm_transfer_output(
            ButtonRequestType_ButtonRequest_ConfirmTransferToAccount,
            amount_str, node_str))
      return TXOUT_CANCEL;
    *needs_confirm = false;
  }

  /* `node` is the shared fsm_derived_node scratch, scrubbed only by the NEXT
   * derivation or by fsm_abort_workflows(). Neither runs on the error paths
   * below: fsm_msgEthereumSignTx answers a compile error with
   * ethereum_signing_abort(), which scrubs ethereum.c's own privkey and
   * nothing else. So every exit past this point has to scrub the node itself,
   * exactly as fsm_msgEthereumSignTypedHash does. */
  const HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->to_address_n,
                                          msg->to_address_n_count, NULL);
  if (!node) return TXOUT_COMPILE_ERROR;

  uint8_t to_bytes[20];
  if (!hdnode_get_ethereum_pubkeyhash(node, to_bytes)) {
    fsm_clearDerivedNode();
    return TXOUT_COMPILE_ERROR;
  }

  if (ethereum_isStandardERC20Transfer(msg)) {
    if (memcmp(msg->data_initial_chunk.bytes + 4 + (32 - 20), to_bytes, 20) !=
        0) {
      fsm_clearDerivedNode();
      return TXOUT_COMPILE_ERROR;
    }
  } else {
    msg->has_to = true;
    msg->to.size = 20;
    memcpy(msg->to.bytes, to_bytes, sizeof(to_bytes));
  }

  fsm_clearDerivedNode();
  return TXOUT_OK;
}

static int process_ethereum_msg(EthereumSignTx* msg, bool* needs_confirm) {
  const CoinType* coin = fsm_getCoin(true, ETHEREUM);
  if (!coin) return TXOUT_COMPILE_ERROR;

  switch (msg->address_type) {
    case OutputAddressType_TRANSFER: {
      // prep transfer type transaction
      return process_ethereum_xfer(coin, msg, needs_confirm);
    }
    default:
      return TXOUT_OK;
  }
}

static void continue_ethereum_sign_tx(EthereumSignTx* msg) {
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

void fsm_msgEthereumSignTx(EthereumSignTx* msg) {
  /* A new start supersedes any old Ethereum stream before validation. */
  ethereum_signing_abort();

  CHECK_INITIALIZED

  CHECK_PIN

  /* Validate the replay-protection domain before any transaction-specific
   * review. process_ethereum_msg() can draw a transfer-to-account screen, so
   * leaving this to ethereum_signing_init() meant OutputAddressType_TRANSFER
   * emitted a ButtonRequest before an omitted chain_id was refused. */
  if (!ethereum_chainIdIsValid(msg)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Chain Id out of bounds"));
    layoutHome();
    return;
  }

  continue_ethereum_sign_tx(msg);
}

void fsm_msgEthereumTxAck(EthereumTxAck* msg) { ethereum_signing_txack(msg); }

void fsm_msgEthereumTxMetadata(const EthereumTxMetadata* msg) {
  CHECK_INITIALIZED
  if (!storage_isPolicyEnabled("AdvancedMode")) {
    ethereum_signing_abort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("AdvancedMode required for clearsign metadata"));
    layoutHome();
    return;
  }
  CHECK_PIN

  /* Metadata during signing never reaches here: the dispatch hook refuses
   * it (see keepkey_before_message_dispatch()). */

  /* Range-check the uint32 wire value against the slot count BEFORE it is
   * narrowed to the uint8 slot index below: (uint8_t)256 would alias slot 0.
   * A slot that cannot exist is a malformed request, not an "Invalid"
   * classification. */
  CHECK_PARAM(!msg->has_key_id || msg->key_id < METADATA_MAX_KEYS,
              _("clearsign metadata key_id out of range"));

  RESP_INIT(EthereumMetadataAck);

  MetadataClassification result = signed_metadata_process(
      msg->signed_payload.bytes, msg->signed_payload.size,
      msg->has_key_id ? (uint8_t)msg->key_id : 0);

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

  /* A signer load during signing never reaches here: the dispatch hook
   * refuses it (see keepkey_before_message_dispatch()). */

  CHECK_PARAM(storage_isPolicyEnabled("AdvancedMode"),
              _("AdvancedMode required for clearsign signers"));

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
     * wire; signed_metadata_signer_icon() rechecks the session copy at use. */
    CHECK_PARAM(msg->has_icon_width && msg->has_icon_height &&
                    msg->icon_width > 0 &&
                    msg->icon_width <= LEFT_MARGIN_WITH_ICON &&
                    msg->icon_height > 0 && msg->icon_height <= 64,
                _("icon dimensions out of range"));
    /* Reject a malformed RLE stream HERE rather than discovering it at draw
     * time. The render path returns a bool that layout_add_icon() discards, so
     * an undecodable icon would otherwise show no logo while still returning
     * Success — the user would consent to an identity
     * whose logo silently does not exist. Validation is exact (every packet
     * well-formed, no run straddling the image, whole input consumed) and
     * side-effect-free.
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
  CHECK_PARAM(!persist, _("Persistent clearsign signers are disabled"));

  /* Mandatory on-device consent — leads with the identity's logo (if any) +
   * alias + fingerprint. The whole trust model hangs on this confirm; the same
   * fingerprint reappears on every per-tx identity screen. */
  char fingerprint[METADATA_FINGERPRINT_LEN];
  signed_metadata_pubkey_fingerprint(msg->pubkey.bytes, fingerprint);
  if (!signed_metadata_confirm_load(msg->alias, fingerprint, icon, icon_w,
                                    icon_h, icon_len)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("Load clearsign signer cancelled"));
    layoutHome();
    return;
  }

  if (!signed_metadata_store_signer((uint8_t)msg->key_id, msg->pubkey.bytes,
                                    msg->alias, icon, icon_w, icon_h, icon_len,
                                    persist)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Clearsign signer could not be loaded"));
    layoutHome();
    return;
  }
  fsm_sendSuccess(_("Clearsign signer loaded"));
  layoutHome();
}

void fsm_msgEthereumGetAddress(EthereumGetAddress* msg) {
  RESP_INIT(EthereumAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  /* Build the whole answer in LOCALS and commit it to `resp` only after the
   * confirmation.
   *
   * `resp` aliases fsm.c's single msg_resp buffer, and confirm_* below runs a
   * message loop: every DebugLink request the emulator harness makes while a
   * screen is up is dispatched from inside it, and those handlers RESP_INIT
   * the same buffer. Anything staged in `resp` before the screen is therefore
   * live across an arbitrary number of foreign writes to it -- which is how
   * EthereumAddress.address_str reached the host as undecodable bytes.
   *
   * fsm_msgNanoGetAddress() already builds into a local and assigns after its
   * confirm; this handler was the one that staged first. */
  uint8_t pubkeyhash[20] = {0};

  if (!hdnode_get_ethereum_pubkeyhash(node, pubkeyhash)) {
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
  ethereum_address_checksum(pubkeyhash, address + 2, rskip60, chain_id);

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

  /* Only now, with no further message loop between here and the write. */
  resp->address.size = sizeof(pubkeyhash);
  memcpy(resp->address.bytes, pubkeyhash, sizeof(pubkeyhash));
  resp->has_address_str = true;
  strlcpy(resp->address_str, address, sizeof(resp->address_str));

  msg_write(MessageType_MessageType_EthereumAddress, resp);
  layoutHome();
}

// cppcheck-suppress constParameterPointer -- protobuf dispatcher ABI is mutable
void fsm_msgEthereumSignMessage(EthereumSignMessage* msg) {
  RESP_INIT(EthereumMessageSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  /* A zero-length message is not a message. confirm_bytes() renders size 0 as
     the literal "(empty)" and returns whatever the owner pressed, so without
     this the device would sign a payload no screen ever showed -- the same
     hole already closed on the TON and Solana paths. (`message` is a required
     field here, so nanopb rejects an omitted one during decode; only the empty
     case reaches this far.) */
  if (msg->message.size == 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Missing message"));
    layoutHome();
    return;
  }

  /* Merge note (#432 vs this branch): release/7.14.2 gated Ethereum message
   * signing behind AdvancedMode, which blocks every Sign-In-With-Ethereum flow
   * on a default device until the user explicitly enables blind signing.
   * AdvancedMode is session-scoped and is cleared on lock.
   * confirm_bytes() paginates and displays EVERY signed byte, which is what
   * that gate was standing in for. Full disclosure is both the stronger
   * security property and the one that does not break default-configuration
   * signing, so the gate is dropped here in favour of it. */
  if (!confirm_bytes(ButtonRequestType_ButtonRequest_ProtectCall,
                     _("Sign Ethereum Message"), msg->message.bytes,
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
                     _("Ethereum Message Verified"), msg->message.bytes,
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

  if (!ethereum_typed_hash_policy_allows(
          storage_isPolicyEnabled("AdvancedMode"))) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Enable AdvancedMode to blind-sign typed hashes"));
    layoutHome();
    return;
  }

  if (msg->domain_separator_hash.size != 32 ||
      (msg->has_message_hash && msg->message_hash.size != 32)) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid EIP-712 hash length"));
    return;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_Other, "EIP-712 Blind Sign",
               "Cannot verify these hashes. Trust the host?")) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  /* Not const: every exit past this point has to scrub the node.
   *
   * `node` is the shared fsm_derived_node scratch. A Cancel answered at any of
   * the confirmations below is consumed by confirm_screen() and returned as a
   * refusal -- it never reaches fsm_msgCancel(), so nothing else runs
   * fsm_abort_workflows() on the way out. Each early return here was therefore
   * leaving a derived private key resident, and so was the success path. */
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  uint8_t pubkeyhash[20] = {0};
  if (!hdnode_get_ethereum_pubkeyhash(node, pubkeyhash)) {
    memzero(node, sizeof(*node));
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
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  for (ctr = 0; ctr < 64 / 2; ctr++) {
    snprintf(&str[2 * ctr], 3, "%02x", msg->domain_separator_hash.bytes[ctr]);
  }
  if (!confirm(ButtonRequestType_ButtonRequest_Other, "Typed Data domain",
               "Confirm hash digest: %s", str)) {
    memzero(node, sizeof(*node));
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
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  } else {
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Typed Data message",
                 "Confirm: No message")) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
  }

  ethereum_typed_hash_sign(msg, node, resp);
  memzero(node, sizeof(*node));
  layoutHome();
}

void fsm_msgEthereum712TypesValues(Ethereum712TypesValues* msg) {
  RESP_INIT(EthereumTypedDataSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  if (!ethereum_structured_eip712_enabled()) {
    fsm_sendFailure(
        FailureType_Failure_Other,
        _("Structured EIP-712 disabled pending canonical display hardening"));
    layoutHome();
    return;
  }

  if (strlen(msg->eip712types) == 0) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Invalid EIP-712 types property string"));
    return;
  }

  /* Not const, for the same reason as fsm_msgEthereumSignTypedHash() above:
   * this is the shared fsm_derived_node scratch and every exit has to scrub
   * it. e712_types_values() runs its own confirmations, and a Cancel answered
   * there never reaches fsm_msgCancel(). */
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  uint8_t pubkeyhash[20] = {0};
  if (!hdnode_get_ethereum_pubkeyhash(node, pubkeyhash)) {
    memzero(node, sizeof(*node));
    layoutHome();
    return;
  }

  resp->address[0] = '0';
  resp->address[1] = 'x';
  ethereum_address_checksum(pubkeyhash, resp->address + 2, false, 0);

  e712_types_values(msg, resp, node);
  memzero(node, sizeof(*node));

  layoutHome();
}

/* ── Structured EIP-712 ──────────────────────────────────────────────
 *
 * The walk in eip712_stream.c never writes a message. It describes what it
 * wants next and these three handlers emit it, because msg_resp and the HD
 * node live here. One pump serves all three so the wire behaviour has exactly
 * one definition.
 */
static void eip712_pump(void) {
  const Eip712Next* next = eip712_stream_next();

  switch (next->kind) {
    case EIP712_REQ_STRUCT: {
      RESP_INIT(EthereumTypedDataStructRequest);
      strlcpy(resp->name, next->struct_name, sizeof(resp->name));
      note_workflow_progress();
      msg_write(MessageType_MessageType_EthereumTypedDataStructRequest, resp);
      return;
    }
    case EIP712_REQ_VALUE: {
      RESP_INIT(EthereumTypedDataValueRequest);
      resp->member_path_count = next->member_path_len;
      memcpy(resp->member_path, next->member_path,
             next->member_path_len * sizeof(uint32_t));
      resp->has_value_offset = next->has_value_offset;
      resp->value_offset = next->value_offset;
      note_workflow_progress();
      msg_write(MessageType_MessageType_EthereumTypedDataValueRequest, resp);
      return;
    }
    case EIP712_REQ_DONE: {
      /* The walk has finished; keep only its result. */
      const Eip712Next done = *next;
      eip712_stream_abort();
      /* sign(keccak(0x19 || 0x01 || domainSeparator || hashStruct(message))),
       * or keccak(0x19 || 0x01 || domainSeparator) for a domain-only type. */
      uint8_t preimage[66];
      preimage[0] = 0x19;
      preimage[1] = 0x01;
      memcpy(preimage + 2, done.domain_separator, 32);
      memcpy(preimage + 34, done.message_hash, 32);
      uint8_t sighash[32];
      keccak_256(preimage, done.domain_only ? 34 : sizeof(preimage), sighash);

      /* Not const: node is the shared fsm_derived_node scratch and holds a
       * private key, so every exit below scrubs it (same rule as
       * process_ethereum_xfer(); 7.15 audit F059). Neither the node nor the
       * msg_resp arena is held across the confirmation below: a DebugLink
       * request answered during it reuses the arena, and dispatch clears the
       * derived node. The address is kept in a local and the key is derived
       * again only after approval. */
      HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, done.address_n,
                                        done.address_n_count, NULL);
      if (!node) return;
      uint8_t pubkeyhash[20];
      const bool derived = hdnode_get_ethereum_pubkeyhash(node, pubkeyhash);
      memzero(node, sizeof(*node));
      if (!derived) {
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Ethereum address derivation failed"));
        layout_home();
        return;
      }
      char address[2 + 40 + 1];
      address[0] = '0';
      address[1] = 'x';
      ethereum_address_checksum(pubkeyhash, address + 2, false, 0);

      /* The one screen that names the action being authorised and the
       * account authorising it; every leaf before it was part of the review. */
      if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Sign Typed Data",
                   "Sign %s%s%s\nfrom %s?",
                   done.message_empty && !done.domain_only ? "EMPTY " : "",
                   done.primary_type, done.domain_only ? " (domain only)" : "",
                   address)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        _("Signing cancelled by user"));
        layout_home();
        return;
      }

      node = fsm_getDerivedNode(SECP256K1_NAME, done.address_n,
                                done.address_n_count, NULL);
      if (!node) return;
      uint8_t sig[64];
      uint8_t v = 0;
      const int signed_rc = ecdsa_sign_digest(&secp256k1, node->private_key,
                                              sighash, sig, &v, NULL);
      memzero(node, sizeof(*node));
      if (signed_rc != 0) {
        fsm_sendFailure(FailureType_Failure_Other, _("Signing failed"));
        layout_home();
        return;
      }
      RESP_INIT(EthereumTypedDataSignature);
      memcpy(resp->address, address, sizeof(address));
      resp->signature.size = 65;
      memcpy(resp->signature.bytes, sig, 64);
      resp->signature.bytes[64] = 27 + v;
      resp->has_domain_separator_hash = true;
      resp->domain_separator_hash.size = 32;
      memcpy(resp->domain_separator_hash.bytes, done.domain_separator, 32);
      resp->has_msg_hash = !done.domain_only;
      resp->has_message_hash = !done.domain_only;
      resp->message_hash.size = done.domain_only ? 0 : 32;
      memcpy(resp->message_hash.bytes, done.message_hash, 32);
      msg_write(MessageType_MessageType_EthereumTypedDataSignature, resp);
      layout_home();
      return;
    }
    case EIP712_REQ_CANCELLED:
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("EIP-712 cancelled"));
      layout_home();
      return;
    case EIP712_REQ_FAIL:
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      next->error ? next->error : "EIP-712 error");
      layout_home();
      return;
    default:
      fsm_sendFailure(FailureType_Failure_Other, _("EIP-712 internal state"));
      layout_home();
      return;
  }
}

void fsm_msgEthereumSignTypedData(const EthereumSignTypedData* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  /* This is the canonical device-driven stream, not the withdrawn whole-JSON
   * parser and not the blind typed-hash endpoint. Every leaf is validated,
   * rendered and hashed from the same bytes, so AdvancedMode is neither needed
   * nor consulted. */
  if (!ethereum_streamed_eip712_enabled()) {
    fsm_sendFailure(FailureType_Failure_Other,
                    _("Structured EIP-712 is unavailable"));
    layout_home();
    return;
  }

  eip712_stream_begin(msg, false);
  eip712_pump();
}

void fsm_msgEthereumTypedDataStructAck(const EthereumTypedDataStructAck* msg) {
  CHECK_INITIALIZED
  eip712_stream_on_struct(msg);
  eip712_pump();
}

void fsm_msgEthereumTypedDataValueAck(const EthereumTypedDataValueAck* msg) {
  CHECK_INITIALIZED
  eip712_stream_on_value(msg);
  eip712_pump();
}

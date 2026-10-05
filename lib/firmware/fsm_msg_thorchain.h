void fsm_msgThorchainGetAddress(const ThorchainGetAddress* msg) {
  RESP_INIT(ThorchainAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  const CoinType* coin = fsm_getCoin(true, "THORChain");
  if (!coin) {
    return;
  }
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  const char mainnet[] = "thor";
  const char testnet[] = "tthor";
  const char* pfix;

  if (!node) {
    return;
  }

  hdnode_fill_public_key(node);

  pfix = mainnet;
  if (msg->has_testnet && msg->testnet) {
    pfix = testnet;
  }

  if (!tendermint_getAddress(node, pfix, resp->address)) {
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Can't encode address"));
    layoutHome();
    return;
  }

  if (msg->has_show_display && msg->show_display) {
    char node_str[NODE_STRING_LENGTH];
    if (!bip32_node_to_string(node_str, sizeof(node_str), coin, msg->address_n,
                              msg->address_n_count, /*whole_account=*/false,
                              /*show_addridx=*/false) &&
        !bip32_path_to_string(node_str, sizeof(node_str), msg->address_n,
                              msg->address_n_count)) {
      memset(node_str, 0, sizeof(node_str));
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Can't create Bip32 Path String"));
      layoutHome();
    }

    bool mismatch =
        tendermint_pathMismatched(coin, msg->address_n, msg->address_n_count);
    if (mismatch) {
      if (!confirm(ButtonRequestType_ButtonRequest_Other, "WARNING",
                   "Wrong address path for selected coin. Continue at your own "
                   "risk!")) {
        memzero(node, sizeof(*node));
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }
    }

    if (!confirm_ethereum_address(node_str, resp->address)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Show address cancelled");
      layoutHome();
      return;
    }
  }

  resp->has_address = true;

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_ThorchainAddress, resp);
  layoutHome();
}

void fsm_msgThorchainSignTx(const ThorchainSignTx* msg) {
  CHECK_INITIALIZED

  if (!msg->has_account_number || !msg->has_chain_id || !msg->has_fee_amount ||
      !msg->has_gas || !msg->has_sequence || !msg->has_msg_count ||
      msg->msg_count == 0 || !tendermint_validateSafeText(msg->chain_id)) {
    thorchain_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Missing or Invalid Fields On Message");
    layoutHome();
    return;
  }

  /* Reject malformed envelopes before authentication or key derivation. */
  CHECK_PIN

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) {
    return;
  }

  hdnode_fill_public_key(node);

  RESP_INIT(ThorchainMsgRequest);

  if (!thorchain_signTxInit(node, msg)) {
    thorchain_signAbort();
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to initialize transaction signing"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_ThorchainMsgRequest, resp);
  layoutHome();
}

void fsm_msgThorchainMsgAck(const ThorchainMsgAck* msg) {
  // Confirm transaction basics
  // supports only 1 message ack
  CHECK_PARAM(thorchain_signingIsInited(), "Signing not in progress");
  if (msg->has_send && msg->send.has_to_address && msg->send.has_amount) {
    // pass
  } else if (msg->has_deposit && msg->deposit.has_asset &&
             msg->deposit.has_amount && msg->deposit.has_memo &&
             msg->deposit.has_signer) {
    // pass
  } else {
    thorchain_signAbort();
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Invalid THORChain Message Type"));
    layoutHome();
    return;
  }

  const CoinType* coin = fsm_getCoin(true, "THORChain");
  if (!coin) {
    return;
  }

  const ThorchainSignTx* sign_tx = thorchain_getThorchainSignTx();

  if (msg->has_send) {
    switch (msg->send.address_type) {
      case OutputAddressType_TRANSFER:
      default: {
        char amount_str[32];
        if (!thorchain_formatAmount(msg->send.amount, "RUNE", amount_str,
                                    sizeof(amount_str))) {
          thorchain_signAbort();
          fsm_sendFailure(FailureType_Failure_SyntaxError,
                          "Invalid THORChain send amount");
          layoutHome();
          return;
        }
        /* Validate the recipient BEFORE the screen, not in the serializer.
           thorchain_signTxUpdateMsgSend() already refuses a
           malformed or wrong-network address, but it runs after this
           confirmation, so the owner approved a transfer that was then
           rejected. This release line's rule is that an invalid signed value
           fails before approval, so the same check moves ahead of the
           screen. */
        if (!tendermint_validateBech32Address(
                msg->send.to_address,
                sign_tx->has_testnet && sign_tx->testnet ? "tthor" : "thor")) {
          thorchain_signAbort();
          fsm_sendFailure(FailureType_Failure_SyntaxError,
                          "Invalid THORChain recipient address");
          layoutHome();
          return;
        }
        if (!confirm_transaction_output(
                ButtonRequestType_ButtonRequest_ConfirmOutput, amount_str,
                msg->send.to_address)) {
          thorchain_signAbort();
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          layoutHome();
          return;
        }

        break;
      }
    }
    if (!thorchain_signTxUpdateMsgSend(msg->send.amount,
                                       msg->send.to_address)) {
      thorchain_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include send message in transaction");
      layoutHome();
      return;
    }

  } else if (msg->has_deposit) {
    const char* const signer_prefix =
        sign_tx->has_testnet && sign_tx->testnet ? "tthor" : "thor";
    /* The signer must be THIS session's account, not merely a well-formed
       address on the right network. MsgDeposit serializes `signer` verbatim as
       the message authority, so a valid-but-foreign address produced a signed
       document the device's key cannot authorize -- and the confirmation below
       labels that address as though it were a destination, so the screen would
       not have given it away. */
    if (!tendermint_validateSafeText(msg->deposit.asset) ||
        !tendermint_validateBech32Address(msg->deposit.signer, signer_prefix) ||
        !thorchain_addressIsSigner(msg->deposit.signer)) {
      thorchain_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Invalid THORChain deposit fields");
      layoutHome();
      return;
    }

    /* ThorchainMsgDeposit.asset is max_size:20, so the suffix reaches 20
     * characters while a uint64 at 8 decimals reaches 21: 21 + 20 + 1 = 42
     * did not fit the old 32-byte amount_str. bn_format() zeroes its output
     * and returns 0 on overflow, and the ignored return let an EMPTY amount
     * reach the confirmation screen and be signed. Size for the maximum and
     * fail closed, as fsm_msg_binance.h does. */
    char amount_str[21 + THORCHAIN_ASSET_SUFFIX_LEN + 1];
    if (!thorchain_formatAmount(msg->deposit.amount, msg->deposit.asset,
                                amount_str, sizeof(amount_str))) {
      thorchain_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Invalid THORChain deposit amount");
      layoutHome();
      return;
    }
    if (!confirm_transaction_output(
            ButtonRequestType_ButtonRequest_ConfirmOutput, amount_str,
            msg->deposit.signer)) {
      thorchain_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (msg->deposit.has_memo) {
      // See if we can parse the memo
      /* strnlen, not sizeof: passing the buffer capacity hands the parser
         every trailing zero byte in the fixed array as if it were memo
         content. The length that matters is how much of the field is
         populated. */
      ThorchainMemoResult memo_result = thorchain_parseConfirmMemo(
          msg->deposit.memo,
          strnlen(msg->deposit.memo, sizeof(msg->deposit.memo)));
      if (memo_result == THORCHAIN_MEMO_CANCELLED) {
        // A memo screen was refused: a refusal to sign, not a parse failure.
        thorchain_signAbort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }
      if (memo_result == THORCHAIN_MEMO_UNPARSED) {
        /* Memo not recognizable, ask to confirm it.
           confirm_bytes(), not confirm("%s"): "%s" stops at the first NUL, so
           an unparsed memo carrying an embedded zero byte would be signed with
           its tail hidden -- the same defect the parser now refuses, moved one
           screen later. confirm_bytes takes an explicit length and escapes
           every non-printable byte, so the NUL is visible as \x00. */
        if (!confirm_bytes(
                ButtonRequestType_ButtonRequest_ConfirmMemo, _("Memo"),
                (const uint8_t*)msg->deposit.memo,
                strnlen(msg->deposit.memo, sizeof(msg->deposit.memo)))) {
          thorchain_signAbort();
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          layoutHome();
          return;
        }
      }
    }

    if (!thorchain_signTxUpdateMsgDeposit(&(msg->deposit))) {
      thorchain_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include deposit message in transaction");
      layoutHome();
      return;
    }
  }

  if (!thorchain_signingIsFinished()) {
    RESP_INIT(ThorchainMsgRequest);
    msg_write(MessageType_MessageType_ThorchainMsgRequest, resp);
    return;
  }

  /* Review the OUTER transaction memo whenever it is present -- including when
   * the deposit carries one of its own.
   *
   * These are two different strings in the signed document, not one superseding
   * the other: thorchain_signTxInit() hashes sign_tx->memo into the StdSignDoc
   * "memo" field, and the MsgDeposit value below hashes deposit.memo
   * separately. Skipping this review when deposit.has_memo let a host show a
   * benign deposit memo while a different outer memo was signed unseen -- the
   * exact thing this release line exists to prevent. Both are signed, so both
   * are shown. */
  if (sign_tx->has_memo) {
    // See if we can parse the tx memo.
    /* strnlen, not sizeof -- see the deposit path above. */
    ThorchainMemoResult memo_result = thorchain_parseConfirmMemo(
        sign_tx->memo, strnlen(sign_tx->memo, sizeof(sign_tx->memo)));
    if (memo_result == THORCHAIN_MEMO_CANCELLED) {
      // A memo screen was refused: a refusal to sign, not a parse failure.
      thorchain_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
    if (memo_result == THORCHAIN_MEMO_UNPARSED) {
      /* Memo not recognizable, ask to confirm it -- length-aware, see above. */
      if (!confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmMemo, _("Memo"),
                         (const uint8_t*)sign_tx->memo,
                         strnlen(sign_tx->memo, sizeof(sign_tx->memo)))) {
        thorchain_signAbort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }
    }
  }

  char node_str[NODE_STRING_LENGTH];
  if (!bip32_node_to_string(node_str, sizeof(node_str), coin,
                            sign_tx->address_n, sign_tx->address_n_count,
                            /*whole_account=*/false,
                            /*show_addridx=*/false) &&
      !bip32_path_to_string(node_str, sizeof(node_str), sign_tx->address_n,
                            sign_tx->address_n_count)) {
    memset(node_str, 0, sizeof(node_str));
  }

  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, node_str,
               "Sign RUNE on %s? Fee: %" PRIu32 " rune. Gas: %" PRIu32 ".",
               sign_tx->chain_id, sign_tx->fee_amount, sign_tx->gas)) {
    thorchain_signAbort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  RESP_INIT(ThorchainSignedTx);

  if (!thorchain_signTxFinalize(resp->public_key.bytes,
                                resp->signature.bytes)) {
    thorchain_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Failed to finalize signature");
    layoutHome();
    return;
  }

  resp->public_key.size = 33;
  resp->has_public_key = true;
  resp->signature.size = 64;
  resp->has_signature = true;
  thorchain_signAbort();
  layoutHome();
  msg_write(MessageType_MessageType_ThorchainSignedTx, resp);
}


void fsm_msgMayachainGetAddress(const MayachainGetAddress* msg) {
  RESP_INIT(MayachainAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  const CoinType* coin = fsm_getCoin(true, "MAYAChain");
  if (!coin) {
    return;
  }
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  const char mainnet[] = "maya";
  const char testnet[] = "smaya";
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
  msg_write(MessageType_MessageType_MayachainAddress, resp);
  layoutHome();
}

void fsm_msgMayachainSignTx(const MayachainSignTx* msg) {
  CHECK_INITIALIZED

  if (!msg->has_account_number || !msg->has_chain_id || !msg->has_fee_amount ||
      !msg->has_gas || !msg->has_sequence || !msg->has_msg_count ||
      msg->msg_count == 0 || !tendermint_validateSafeText(msg->chain_id)) {
    mayachain_signAbort();
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

  RESP_INIT(MayachainMsgRequest);

  if (!mayachain_signTxInit(node, msg)) {
    mayachain_signAbort();
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to initialize transaction signing"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_MayachainMsgRequest, resp);
  layoutHome();
}

void fsm_msgMayachainMsgAck(const MayachainMsgAck* msg) {
  // Confirm transaction basics
  // supports only 1 message ack
  CHECK_PARAM(mayachain_signingIsInited(), "Signing not in progress");
  if (msg->has_send && msg->send.has_to_address && msg->send.has_amount &&
      msg->send.has_denom) {
    // pass
  } else if (msg->has_deposit && msg->deposit.has_asset &&
             msg->deposit.has_amount && msg->deposit.has_memo &&
             msg->deposit.has_signer) {
    // pass
  } else {
    mayachain_signAbort();
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Invalid MAYAChain Message Type"));
    layoutHome();
    return;
  }

  const CoinType* coin = fsm_getCoin(true, "MAYAChain");
  if (!coin) {
    return;
  }

  const MayachainSignTx* sign_tx = mayachain_getMayachainSignTx();

  if (msg->has_send) {
    switch (msg->send.address_type) {
      case OutputAddressType_TRANSFER:
      default: {
        /* The denomination buffer being big enough does not make the DISPLAYED
         * amount safe: bn_format() writes into amount_str, and on overflow it
         * zeroes the whole buffer and returns 0. Ignoring that return put an
         * EMPTY amount on the confirmation screen and signed anyway -- an
         * amount of 1 with a 19-character denomination already needs 33 bytes,
         * and the signer's 65-byte segment accepts far longer ones.
         *
         * Size for the protocol maximum instead of hoping: a uint64 rendered
         * at 10 decimals is at most 20 digits plus a point (21), the suffix is
         * ' ' + 68 visible chars of denom (69), plus NUL. Then CHECK the
         * result and fail closed, as fsm_msg_binance.h does. See GH #437. */
        char amount_str[21 + MAYACHAIN_DENOM_SUFFIX_LEN + 1];
        /* MayachainMsgSend.denom max_size:69 (messages-mayachain.options) ->
         * 68 visible chars + NUL. ' ' + 68 + NUL = 70 bytes; 71 keeps a 1-byte
         * margin. The prior code used unbounded sprintf(); switch to a bounded
         * snprintf so a future max_size bump can't silently overflow. */
        if (!mayachain_formatAmount(msg->send.amount, msg->send.denom,
                                    amount_str, sizeof(amount_str))) {
          mayachain_signAbort();
          fsm_sendFailure(FailureType_Failure_SyntaxError,
                          "Invalid MAYAChain send amount");
          layoutHome();
          return;
        }
        if (!confirm_transaction_output(
                ButtonRequestType_ButtonRequest_ConfirmOutput, amount_str,
                msg->send.to_address)) {
          mayachain_signAbort();
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          layoutHome();
          return;
        }

        break;
      }
    }
    if (!mayachain_signTxUpdateMsgSend(msg->send.amount, msg->send.to_address,
                                       msg->send.denom)) {
      mayachain_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include send message in transaction");
      layoutHome();
      return;
    }

  } else if (msg->has_deposit) {
    const char* const signer_prefix =
        sign_tx->has_testnet && sign_tx->testnet ? "smaya" : "maya";
    if (!tendermint_validateSafeText(msg->deposit.asset) ||
        !tendermint_validateBech32Address(msg->deposit.signer, signer_prefix)) {
      mayachain_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Invalid MAYAChain deposit fields");
      layoutHome();
      return;
    }

    /* Same defect as the send path above, one field narrower:
     * MayachainMsgDeposit.asset is max_size:20, so the suffix reaches 20
     * characters and 21 + 20 + 1 = 42 does not fit a 32-byte amount_str.
     * bn_format() then zeroed it and returned 0, and the ignored return let an
     * empty amount reach the screen. */
    char amount_str[21 + MAYACHAIN_ASSET_SUFFIX_LEN + 1];
    if (!mayachain_formatAmount(msg->deposit.amount, msg->deposit.asset,
                                amount_str, sizeof(amount_str))) {
      mayachain_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Invalid MAYAChain deposit amount");
      layoutHome();
      return;
    }
    if (!confirm_transaction_output(
            ButtonRequestType_ButtonRequest_ConfirmOutput, amount_str,
            msg->deposit.signer)) {
      mayachain_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (msg->deposit.has_memo) {
      // See if we can parse the memo
      /* strnlen, not sizeof: the capacity of a fixed array is not the length
         of the memo in it. Mirrors the THORChain path. */
      MayachainMemoResult memo_result = mayachain_parseConfirmMemo(
          msg->deposit.memo,
          strnlen(msg->deposit.memo, sizeof(msg->deposit.memo)));
      if (memo_result == MAYACHAIN_MEMO_CANCELLED) {
        // A memo screen was refused: a refusal to sign, not a parse failure.
        // Re-asking with the raw-bytes screen would launder that "no" into a
        // second chance to say yes.
        mayachain_signAbort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }
      if (memo_result == MAYACHAIN_MEMO_UNPARSED) {
        // Memo not recognizable, ask to confirm it
        /* confirm_bytes, not confirm("%s"): "%s" stops at the first NUL, so
           an unparsed memo with an embedded zero would be signed with its tail
           hidden. Takes an explicit length and escapes non-printables. */
        if (!confirm_bytes(
                ButtonRequestType_ButtonRequest_ConfirmMemo, _("Memo"),
                (const uint8_t*)msg->deposit.memo,
                strnlen(msg->deposit.memo, sizeof(msg->deposit.memo)))) {
          mayachain_signAbort();
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          layoutHome();
          return;
        }
      }
    }

    if (!mayachain_signTxUpdateMsgDeposit(&(msg->deposit))) {
      mayachain_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include deposit message in transaction");
      layoutHome();
      return;
    }
  }

  if (!mayachain_signingIsFinished()) {
    RESP_INIT(MayachainMsgRequest);
    msg_write(MessageType_MessageType_MayachainMsgRequest, resp);
    return;
  }

  if (sign_tx->has_memo && !msg->deposit.has_memo) {
    // See if we can parse the tx memo. This memo ignored if deposit msg has
    // memo
    MayachainMemoResult memo_result = mayachain_parseConfirmMemo(
        sign_tx->memo, strnlen(sign_tx->memo, sizeof(sign_tx->memo)));
    if (memo_result == MAYACHAIN_MEMO_CANCELLED) {
      // A memo screen was refused: a refusal to sign, not a parse failure.
      mayachain_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }
    if (memo_result == MAYACHAIN_MEMO_UNPARSED) {
      // Memo not recognizable, ask to confirm it -- length-aware, see above.
      if (!confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmMemo, _("Memo"),
                         (const uint8_t*)sign_tx->memo,
                         strnlen(sign_tx->memo, sizeof(sign_tx->memo)))) {
        mayachain_signAbort();
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
               "Sign %s on %s? Fee: %" PRIu32 " cacao. Gas: %" PRIu32 ".",
               msg->has_send ? msg->send.denom : "CACAO", sign_tx->chain_id,
               sign_tx->fee_amount, sign_tx->gas)) {
    mayachain_signAbort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  RESP_INIT(MayachainSignedTx);

  if (!mayachain_signTxFinalize(resp->public_key.bytes,
                                resp->signature.bytes)) {
    mayachain_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Failed to finalize signature");
    layoutHome();
    return;
  }

  resp->public_key.size = 33;
  resp->has_public_key = true;
  resp->signature.size = 64;
  resp->has_signature = true;
  mayachain_signAbort();
  layoutHome();
  msg_write(MessageType_MessageType_MayachainSignedTx, resp);
}

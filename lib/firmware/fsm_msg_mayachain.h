
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
  CHECK_PIN

  if (!msg->has_account_number || !msg->has_chain_id || !msg->has_fee_amount ||
      !msg->has_gas || !msg->has_sequence) {
    mayachain_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Missing Fields On Message");
    layoutHome();
    return;
  }

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

  // Default to "cacao" for backward compatibility; validate all non-default
  // denoms before any display so untrusted strings never reach the UI or
  // the signing JSON.
  const char* coin_denom =
      (msg->has_send && msg->send.has_denom && msg->send.denom[0])
          ? msg->send.denom
          : "cacao";

  if (msg->has_send) {
    if (!mayachain_isValidDenom(coin_denom)) {
      mayachain_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError, "Invalid denom");
      layoutHome();
      return;
    }

    switch (msg->send.address_type) {
      case OutputAddressType_TRANSFER:
      default: {
        // Amount (no denom suffix) must fit amount_str[32]; a long denom
        // appended here would overflow bn_format and blank the amount while
        // the real value is still signed. Confirm the denom on its own
        // screen instead (matches the THORChain send path).
        char amount_str[32];
        if (!bn_format_uint64(msg->send.amount, NULL, NULL, 10, 0, false,
                              amount_str, sizeof(amount_str))) {
          mayachain_signAbort();
          fsm_sendFailure(FailureType_Failure_FirmwareError,
                          _("Failed to format amount"));
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
        if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Asset",
                     "%s", coin_denom)) {
          mayachain_signAbort();
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          layoutHome();
          return;
        }

        break;
      }
    }
    if (!mayachain_signTxUpdateMsgSend(msg->send.amount, msg->send.to_address,
                                       coin_denom)) {
      mayachain_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include send message in transaction");
      layoutHome();
      return;
    }

  } else if (msg->has_deposit) {
    // Validate before any display so untrusted strings never reach the UI
    // or the sign bytes.
    if (!mayachain_isValidAsset(msg->deposit.asset) ||
        !mayachain_isValidSigner(msg->deposit.signer)) {
      mayachain_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Invalid deposit asset or signer");
      layoutHome();
      return;
    }
    // Long-form assets (e.g.
    // ETH.USDT-0XDAC17F958D2EE523A2206206994597C13D831EC7) are ~50 chars;
    // amount_str must fit amount + asset suffix or bn_format zeroes it out.
    char amount_str[96];
    char asset_str[64];
    asset_str[0] = ' ';
    strlcpy(&(asset_str[1]), msg->deposit.asset, sizeof(asset_str) - 1);
    bn_format_uint64(msg->deposit.amount, NULL, asset_str, 10, 0, false,
                     amount_str, sizeof(amount_str));
    if (!confirm_transaction_output(
            ButtonRequestType_ButtonRequest_ConfirmOutput, amount_str,
            msg->deposit.signer)) {
      mayachain_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (msg->deposit.has_memo) {
      size_t memo_len = strnlen(msg->deposit.memo, sizeof(msg->deposit.memo));
      // Page the complete raw memo as the sole, authoritative disclosure (no
      // structured pre-parse: its bool return conflates unrecognized with user
      // reject, so a reject must not be followed by these pages then signing).
      if (!thorchain_confirm_full_memo(_("Memo"), msg->deposit.memo,
                                       memo_len)) {
        mayachain_signAbort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
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
    // Ignored if the deposit msg has a memo. Page the full raw memo as the sole
    // gate (see the deposit path above for why there is no structured pass).
    size_t memo_len = strnlen(sign_tx->memo, sizeof(sign_tx->memo));
    if (!thorchain_confirm_full_memo(_("Memo"), sign_tx->memo, memo_len)) {
      mayachain_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
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
               "Sign this %s transaction on %s? "
               "Additional network fees apply.",
               msg->has_send ? coin_denom : "CACAO", sign_tx->chain_id)) {
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

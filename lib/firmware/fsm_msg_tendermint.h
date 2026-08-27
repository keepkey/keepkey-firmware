
void fsm_msgTendermintGetAddress(const TendermintGetAddress* msg) {
  RESP_INIT(TendermintAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  const CoinType* coin = fsm_getCoin(true, msg->chain_name);
  if (!coin) {
    return;
  }
  /* The HRP comes from the coin, not from chain_name -- coinByName() matches
     case-insensitively, so a request naming "Cosmos" would otherwise derive
     "Cosmos1..." addresses that no Cosmos node would accept, and that the
     signing path would then refuse as wrong-network. */
  /* Gate on the STRING, not coin->has_bech32_prefix. In coins.def the
     tendermint family carries a populated prefix behind a false flag --
     Cosmos is `false, "cosmos"`, Osmosis `false, "osmo"`, THORChain
     `false, "thor"` -- while Binance and Bitcoin set the flag. Requiring the
     flag would refuse every Cosmos transaction. */
  if (coin->bech32_prefix[0] == '\0') {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Coin has no bech32 prefix");
    layoutHome();
    return;
  }
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) {
    return;
  }

  hdnode_fill_public_key(node);

  if (!tendermint_getAddress(node, coin->bech32_prefix, resp->address)) {
    memzero((void*)node, sizeof(*node));
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
  msg_write(MessageType_MessageType_TendermintAddress, resp);
  layoutHome();
}

void fsm_msgTendermintSignTx(const TendermintSignTx* msg) {
  CHECK_INITIALIZED

  if (!msg->has_account_number || !msg->has_chain_id || !msg->has_fee_amount ||
      !msg->has_gas || !msg->has_sequence || !msg->has_chain_name ||
      !msg->has_denom || !msg->has_message_type_prefix || !msg->has_msg_count ||
      msg->msg_count == 0 || !tendermint_validateSafeText(msg->chain_id) ||
      !tendermint_validateSafeText(msg->chain_name) ||
      !tendermint_validateSafeText(msg->denom) ||
      !tendermint_validateSafeText(msg->message_type_prefix)) {
    tendermint_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Missing or Invalid Fields On Message");
    layoutHome();
    return;
  }

  CHECK_PIN

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) {
    return;
  }

  hdnode_fill_public_key(node);

  RESP_INIT(TendermintMsgRequest);

  if (!tendermint_signTxInit(node, (void*)msg, sizeof(TendermintSignTx),
                             msg->denom, TENDERMINT_SIGNING_GENERIC)) {
    tendermint_signAbort();
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to initialize transaction signing"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_TendermintMsgRequest, resp);
  layoutHome();
}

void fsm_msgTendermintMsgAck(const TendermintMsgAck* msg) {
  // Confirm transaction basics
  /* A continuation for the WRONG protocol is terminal for the session it
     found, not just for itself.

     Cosmos and generic Tendermint share one signer in signtx_tendermint.c,
     told apart only by signing_type. CHECK_PARAM sends a failure and returns,
     leaving that shared state initialized: a Cosmos session survived a
     Tendermint ACK (and vice versa), the UI went home, and the session stayed
     resumable by a later stale ACK of its own protocol. Clear the shared
     signer first, the way every malformed-ACK path below already does. */
  if (!tendermint_signingIsInited(TENDERMINT_SIGNING_GENERIC)) {
    tendermint_signAbort();
    fsm_sendFailure(FailureType_Failure_Other,
                    "Tendermint signing not in progress");
    layoutHome();
    return;
  }
  const TendermintSignTx* sign_tx =
      (const TendermintSignTx*)tendermint_getSignTx();
  if (!msg->has_chain_name || !msg->has_denom ||
      !msg->has_message_type_prefix ||
      !tendermint_signingConfigMatches(msg->chain_name, msg->denom,
                                       msg->message_type_prefix)) {
    tendermint_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Tendermint ACK does not match signing session");
    layoutHome();
    return;
  }
  if (!msg->has_send || !msg->send.has_to_address || !msg->send.has_amount) {
    tendermint_signAbort();
    // 8 + ^14 + 13 + 1 = 36
    char failmsg[40];
    snprintf(failmsg, sizeof(failmsg), "Invalid %s Message Type",
             msg->chain_name);

    fsm_sendFailure(FailureType_Failure_FirmwareError, _(failmsg));
    layoutHome();
    return;
  }

  const CoinType* coin = fsm_getCoin(true, msg->chain_name);
  if (!coin) {
    tendermint_signAbort();
    layoutHome();
    return;
  }

  /* Addresses are built from the coin's bech32 prefix, never from chain_name.
   *
   * coinByName() matches with strncasecmp(), so "Cosmos" and "cosmos" both
   * resolve to the same coin -- but only one of them is the HRP. Using
   * chain_name for address work makes correctness depend on the case the host
   * happened to send: a request naming "Cosmos" would reject every valid
   * cosmos1... recipient here and derive a "Cosmos1..." sender in the
   * serializer. coin->bech32_prefix is the single authority for both. */
  /* Gate on the STRING, not coin->has_bech32_prefix. In coins.def the
     tendermint family carries a populated prefix behind a false flag --
     Cosmos is `false, "cosmos"`, Osmosis `false, "osmo"`, THORChain
     `false, "thor"` -- while Binance and Bitcoin set the flag. Requiring the
     flag would refuse every Cosmos transaction. */
  if (coin->bech32_prefix[0] == '\0') {
    tendermint_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Coin has no bech32 prefix");
    layoutHome();
    return;
  }

  switch (msg->send.address_type) {
    case OutputAddressType_TRANSFER:
    default: {
      char amount_str[48];
      const int amount_len =
          snprintf(amount_str, sizeof(amount_str), "%" PRIu64 " %s",
                   msg->send.amount, sign_tx->denom);
      if (amount_len <= 0 || (size_t)amount_len >= sizeof(amount_str)) {
        tendermint_signAbort();
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        "Invalid Tendermint amount display");
        layoutHome();
        return;
      }
      /* Validate the recipient BEFORE the screen, not in the serializer.
         tendermint_signTxUpdateMsgSend() already refuses a
         malformed or wrong-network address, but it runs after this
         confirmation, so the owner approved a transfer that was then
         rejected. This release line's rule is that an invalid signed value
         fails before approval, so the same check moves ahead of the
         screen. */
      if (!tendermint_validateBech32Address(msg->send.to_address,
                                            coin->bech32_prefix)) {
        tendermint_signAbort();
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        "Invalid Tendermint recipient address");
        layoutHome();
        return;
      }
      if (!confirm_transaction_output(
              ButtonRequestType_ButtonRequest_ConfirmOutput, amount_str,
              msg->send.to_address)) {
        tendermint_signAbort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }

      break;
    }
  }

  if (!tendermint_signTxUpdateMsgSend(msg->send.amount, msg->send.to_address,
                                      coin->bech32_prefix, msg->denom,
                                      msg->message_type_prefix)) {
    tendermint_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Failed to include send message in transaction");
    layoutHome();
    return;
  }

  if (!tendermint_signingIsFinished()) {
    RESP_INIT(TendermintMsgRequest);
    msg_write(MessageType_MessageType_TendermintMsgRequest, resp);
    return;
  }

  if (sign_tx->has_memo &&
      !confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmMemo, _("Memo"),
                     (const uint8_t*)sign_tx->memo, strlen(sign_tx->memo))) {
    tendermint_signAbort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (!confirm_bytes(ButtonRequestType_ButtonRequest_Other, "Chain ID",
                     (const uint8_t*)sign_tx->chain_id,
                     strlen(sign_tx->chain_id)) ||
      !confirm_bytes(ButtonRequestType_ButtonRequest_Other, "Chain Name",
                     (const uint8_t*)sign_tx->chain_name,
                     strlen(sign_tx->chain_name)) ||
      !confirm_bytes(ButtonRequestType_ButtonRequest_Other, "Denomination",
                     (const uint8_t*)sign_tx->denom, strlen(sign_tx->denom)) ||
      !confirm_bytes(ButtonRequestType_ButtonRequest_Other, "Message Type",
                     (const uint8_t*)sign_tx->message_type_prefix,
                     strlen(sign_tx->message_type_prefix))) {
    tendermint_signAbort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
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
               "Sign transaction? Fee: %" PRIu32 " %s. Gas: %" PRIu32 ".",
               sign_tx->fee_amount, sign_tx->denom, sign_tx->gas)) {
    tendermint_signAbort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  RESP_INIT(TendermintSignedTx);

  if (!tendermint_signTxFinalize(resp->public_key.bytes,
                                 resp->signature.bytes)) {
    tendermint_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Failed to finalize signature");
    layoutHome();
    return;
  }

  resp->public_key.size = 33;
  resp->has_public_key = true;
  resp->signature.size = 64;
  resp->has_signature = true;
  tendermint_signAbort();
  layoutHome();
  msg_write(MessageType_MessageType_TendermintSignedTx, resp);
}

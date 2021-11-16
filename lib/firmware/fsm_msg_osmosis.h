
void fsm_msgOsmosisGetAddress(const OsmosisGetAddress *msg) {
  RESP_INIT(OsmosisAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  const CoinType *coin = fsm_getCoin(true, "Osmosis");
  if (!coin) {
    return;
  }
  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  char mainnet[] = "osmo";
  char testnet[] = "tosmo";
  char *pfix;

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
  msg_write(MessageType_MessageType_OsmosisAddress, resp);
  layoutHome();
}

void fsm_msgOsmosisSignTx(const OsmosisSignTx *msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  if (!msg->has_account_number || !msg->has_chain_id || !msg->has_fee_amount ||
      !msg->has_gas || !msg->has_sequence) {
    osmosis_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Missing Fields On Message");
    layoutHome();
    return;
  }

  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) {
    return;
  }

  hdnode_fill_public_key(node);

  RESP_INIT(OsmosisMsgRequest);

  if (!osmosis_signTxInit(node, msg)) {
    osmosis_signAbort();
    memzero(node, sizeof(*node));
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to initialize transaction signing"));
    layoutHome();
    return;
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_OsmosisMsgRequest, resp);
  layoutHome();
}

void fsm_msgOsmosisMsgAck(const OsmosisMsgAck *msg) {
  // Confirm transaction basics
  // supports only 1 message ack
  CHECK_PARAM(osmosis_signingIsInited(), "Signing not in progress");
  if (msg->has_send && msg->send.has_to_address && msg->send.has_token &&
      msg->send.token.has_amount) {
    // pass
  } else if (msg->has_delegate && msg->delegate.has_delegator_address &&
             msg->delegate.has_validator_address && msg->delegate.has_token) {
    // pass
  } else if (msg->has_undelegate && msg->undelegate.has_delegator_address &&
             msg->undelegate.has_validator_address &&
             msg->undelegate.has_token) {
    // pass
  } else if (msg->has_claim && msg->claim.has_delegator_address &&
             msg->claim.has_validator_address && msg->claim.has_token) {
    // pass
  } else if (msg->has_lp_add && msg->lp_add.has_sender &&
             msg->lp_add.has_pool_id && msg->lp_add.has_share_out_amount &&
             msg->lp_add.has_token_in_max_a && msg->lp_add.has_token_in_max_b) {
    // pass
  } else if (msg->has_lp_remove && msg->lp_remove.has_sender &&
             msg->lp_remove.has_pool_id &&
             msg->lp_remove.has_share_out_amount &&
             msg->lp_remove.has_token_out_min_a &&
             msg->lp_remove.has_token_out_min_b) {
    // pass
  } else if (msg->has_farm_tokens && msg->farm_tokens.has_owner &&
             msg->farm_tokens.has_duration && msg->farm_tokens.has_token) {
    // pass
  } else if (msg->has_ibc_deposit && msg->ibc_deposit.has_source_port &&
             msg->ibc_deposit.has_source_channel &&
             msg->ibc_deposit.has_token && msg->ibc_deposit.has_sender &&
             msg->ibc_deposit.has_receiver &&
             msg->ibc_deposit.has_timeout_height) {
    // pass
  } else if (msg->has_ibc_withdrawal && msg->ibc_withdrawal.has_source_port &&
             msg->ibc_withdrawal.has_source_channel &&
             msg->ibc_withdrawal.has_token && msg->ibc_withdrawal.has_sender &&
             msg->ibc_withdrawal.has_receiver &&
             msg->ibc_withdrawal.has_timeout_height) {
    // pass
  } else if (msg->has_swap && msg->swap.has_sender && msg->swap.has_pool_id &&
             msg->swap.has_token_out_denom && msg->swap.has_token_in &&
             msg->swap.has_token_out_min_amount) {
    // pass
  } else {
    osmosis_signAbort();
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Invalid Osmosis Message Type"));
    layoutHome();
    return;
  }

  const CoinType *coin = fsm_getCoin(true, "Osmosis");
  if (!coin) {
    return;
  }

  const OsmosisSignTx *sign_tx = osmosis_getOsmosisSignTx();

  if (msg->has_send) {
    switch (msg->send.address_type) {
      case OutputAddressType_TRANSFER:
      default: {
        char amount_str[32];
        bn_format_uint64(msg->send.token.amount, NULL, " OSMO", 8, 0, false,
                         amount_str, sizeof(amount_str));
        if (!confirm(ButtonRequestType_ButtonRequest_Other, "Transfer",
                      "Send %s to %s?", amount_str, msg->send.to_address)) {
          osmosis_signAbort();
          fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
          layoutHome();
          return;
        }

        break;
      }
    }
    if (!osmosis_signTxUpdateMsgSend(msg->send.token.amount,
                                     msg->send.to_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include send message in transaction");
      layoutHome();
      return;
    }

  } else if (msg->has_delegate) {
    char amount_str[32];
    bn_format_uint64(msg->delegate.token.amount, NULL, " OSMO", 8, 0, false,
                     amount_str, sizeof(amount_str));

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Delegate",
                 "Delegate %s to %s?", amount_str,
                 msg->delegate.validator_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgDelegate(&(msg->delegate))) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include delegate message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_undelegate) {
    char amount_str[32];
    bn_format_uint64(msg->undelegate.token.amount, NULL, " OSMO", 8, 0, false,
                     amount_str, sizeof(amount_str));

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Undelegate",
                 "Undelegate %s from %s?", amount_str,
                 msg->undelegate.validator_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgUndelegate(&(msg->undelegate))) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include undelegate message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_claim) {
    char amount_str[32];
    bn_format_uint64(msg->claim.token.amount, NULL, " OSMO", 8, 0, false,
                     amount_str, sizeof(amount_str));
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Claim",
                 "Claim %s from %s?", amount_str,
                 msg->claim.validator_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgClaim(&(msg->claim))) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include claim message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_lp_add) {
    char amount_a_str[32];
    char amount_b_str[32];
    const char *denom_a_str =
        strcmp(msg->lp_add.token_in_max_a.denom, "uosmo") == 0
            ? "OSMO"
            : msg->lp_add.token_in_max_a.denom;
    const char *denom_b_str =
        strcmp(msg->lp_add.token_in_max_b.denom, "uosmo") == 0
            ? "OSMO"
            : msg->lp_add.token_in_max_b.denom;

    bn_format_uint64(msg->lp_add.token_in_max_a.amount, NULL, NULL, 8, 0, false,
                     amount_a_str, sizeof(amount_a_str));

    bn_format_uint64(msg->lp_add.token_in_max_b.amount, NULL, NULL, 8, 0, false,
                     amount_b_str, sizeof(amount_b_str));

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Add Liquidity",
                 "Confirm Token A:\nAmount: %s\nDenom: %s", amount_a_str,
                 denom_a_str)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Add Liquidity",
                 "Confirm Token B:\nAmount: %s\nDenom: %s", amount_b_str,
                 denom_b_str)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Add Liquidity",
                 "Confirm Pool ID: %s", msg->lp_add.pool_id)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgLPAdd(&(msg->lp_add))) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include LP Add message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_lp_remove) {
    char amount_a_str[32];
    char amount_b_str[32];
    const char *denom_a_str =
        strcmp(msg->lp_remove.token_out_min_a.denom, "uosmo") == 0
            ? "OSMO"
            : msg->lp_remove.token_out_min_a.denom;
    const char *denom_b_str =
        strcmp(msg->lp_remove.token_out_min_b.denom, "uosmo") == 0
            ? "OSMO"
            : msg->lp_remove.token_out_min_b.denom;

    bn_format_uint64(msg->lp_remove.token_out_min_a.amount, NULL, NULL, 8, 0,
                     false, amount_a_str, sizeof(amount_a_str));

    bn_format_uint64(msg->lp_remove.token_out_min_b.amount, NULL, NULL, 8, 0,
                     false, amount_b_str, sizeof(amount_b_str));

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Remove Liquidity",
                 "Confirm Token A:\nAmount: %s\nDenom: %s", amount_a_str,
                 denom_a_str)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Remove Liquidity",
                 "Confirm Token B:\nAmount: %s\nDenom: %s", amount_b_str,
                 denom_b_str)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Remove Liquidity",
                 "Confirm Pool ID: %s", msg->lp_remove.pool_id)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgLPRemove(&(msg->lp_remove))) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include LP Remove message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_farm_tokens) {
    char amount_str[32];
    bn_format_uint64(msg->farm_tokens.token.amount, NULL, " OSMO", 8, 0, false,
                     amount_str, sizeof(amount_str));

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Farm Tokens",
                 "Lock %s in %s?", amount_str, msg->farm_tokens.token.denom)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Owner", "%s",
                 msg->farm_tokens.owner)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Duration",
                 "%lld", msg->farm_tokens.duration)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgFarmTokens(&(msg->farm_tokens))) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include Farm Tokens message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_ibc_deposit) {
    char amount_str[32];
    bn_format_uint64(msg->ibc_deposit.token.amount, NULL, " OSMO", 8, 0, false,
                     amount_str, sizeof(amount_str));

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "IBC Deposit",
                 "Send %s on %s to %s?", amount_str,
                 msg->ibc_deposit.source_port,
                 msg->ibc_deposit.source_channel)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other,
                 "Confirm Sender Address", "%s", msg->ibc_deposit.sender)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other,
                 "Confirm Receiver Address", "%s", msg->ibc_deposit.receiver)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgIBCDeposit(&(msg->ibc_deposit))) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include IBC Deposit message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_ibc_withdrawal) {
    char amount_str[32];
    bn_format_uint64(msg->ibc_withdrawal.token.amount, NULL, " OSMO", 8, 0,
                     false, amount_str, sizeof(amount_str));
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "IBC Withdrawal",
                 "Receive %s on %s from %s?", amount_str,
                 msg->ibc_withdrawal.source_port,
                 msg->ibc_withdrawal.source_channel)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other,
                 "Confirm Sender Address", "%s", msg->ibc_withdrawal.sender)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other,
                 "Confirm Receiver Address", "%s",
                 msg->ibc_withdrawal.receiver)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgIBCWithdrawal(&(msg->ibc_withdrawal))) {
      osmosis_signAbort();
      fsm_sendFailure(
          FailureType_Failure_SyntaxError,
          "Failed to include IBC Withdrawal message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_swap) {
    char amount_in_str[32] = {' '};
    char amount_out_str[32] = {' '};
    bn_format_uint64(msg->swap.token_in.amount, NULL, msg->swap.token_in.denom,
                     8, 0, false, amount_in_str + (1 * sizeof(char)),
                     sizeof(amount_in_str));
    bn_format_uint64(
        msg->swap.token_out_min_amount, NULL, msg->swap.token_out_denom, 8, 0,
        false, amount_out_str + (1 * sizeof(char)), sizeof(amount_out_str));

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Swap",
                 "Swap %s for at least %lld?", amount_in_str,
                 msg->swap.token_out_min_amount)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Pool ID", "%s",
                 msg->swap.pool_id)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgSwap(&(msg->swap))) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include Swap message in transaction");
      layoutHome();
      return;
    }
  }

  if (!osmosis_signingIsFinished()) {
    RESP_INIT(OsmosisMsgRequest);
    msg_write(MessageType_MessageType_OsmosisMsgRequest, resp);
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

  RESP_INIT(OsmosisSignedTx);

  if (!osmosis_signTxFinalize(resp->public_key.bytes, resp->signature.bytes)) {
    osmosis_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Failed to finalize signature");
    layoutHome();
    return;
  }

  resp->public_key.size = 33;
  resp->has_public_key = true;
  resp->signature.size = 64;
  resp->has_signature = true;
  osmosis_signAbort();
  layoutHome();
  msg_write(MessageType_MessageType_OsmosisSignedTx, resp);
}
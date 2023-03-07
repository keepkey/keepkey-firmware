#include <math.h>
#define OSMOSIS_PRECISION 6
#define OSMOSIS_LP_ASSET_PRECISION 18

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
  CHECK_PARAM(osmosis_signingIsInited(), "Signing not in progress");

  const CoinType *coin = fsm_getCoin(true, "Osmosis");
  if (!coin) {
    return;
  }

  const OsmosisSignTx *sign_tx = osmosis_getOsmosisSignTx();

  if (msg->has_send) {
    if (!msg->send.has_to_address || !msg->send.has_amount) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    char amount_str[40];
    sprintf(amount_str, "%.6f OSMO",
            atof(msg->send.amount) / pow(10, OSMOSIS_PRECISION));
    if (!confirm_transaction_output(
            ButtonRequestType_ButtonRequest_ConfirmOutput, amount_str,
            msg->send.to_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgSend(msg->send.amount, msg->send.to_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include send message in transaction");
      layoutHome();
      return;
    }

  } else if (msg->has_delegate) {
    /** Confirm required transaction parameters exist */
    if (!msg->delegate.has_delegator_address ||
        !msg->delegate.has_validator_address || !msg->delegate.has_amount) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }
    /** Confirm transaction parameters on-screen */
    if (!confirm_osmosis_address("Confirm Delegator Address",
                                 msg->delegate.delegator_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_osmosis_address("Confirm Validator Address",
                                 msg->delegate.validator_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Amount",
                 "%.6f OSMO",
                 atof(msg->delegate.amount) / pow(10, OSMOSIS_PRECISION))) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgDelegate(
            msg->delegate.amount, msg->delegate.delegator_address,
            msg->delegate.validator_address, msg->delegate.denom)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include delegate message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_undelegate) {
    /** Confirm required transaction parameters exist */
    if (!msg->undelegate.has_delegator_address ||
        !msg->undelegate.has_validator_address || !msg->undelegate.has_amount) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }
    /** Confirm transaction parameters on-screen */

    if (!confirm_osmosis_address("Confirm Delegator Address",
                                 msg->undelegate.delegator_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_osmosis_address("Confirm Validator Address",
                                 msg->undelegate.validator_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Amount",
                 "%.6f OSMO",
                 atof(msg->undelegate.amount) / pow(10, OSMOSIS_PRECISION))) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgUndelegate(
            msg->undelegate.amount, msg->undelegate.delegator_address,
            msg->undelegate.validator_address, msg->undelegate.denom)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include undelegate message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_lp_add) {
    /** Confirm required transaction parameters exist */
    if (!msg->lp_add.has_sender || !msg->lp_add.has_pool_id ||
        !msg->lp_add.has_share_out_amount || !msg->lp_add.has_denom_in_max_a ||
        !msg->lp_add.has_amount_in_max_a || !msg->lp_add.has_denom_in_max_b ||
        !msg->lp_add.has_amount_in_max_b) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    /** Confirm transaction parameters on-screen */
    char insoamt[33] = {0};
    uint8_t outsoamt[34] = {0};
    strlcpy(insoamt, msg->lp_add.share_out_amount,
            sizeof(msg->lp_add.share_out_amount));

    if (base_to_precision(outsoamt, (uint8_t *)insoamt, sizeof(outsoamt),
                          strlen(insoamt), OSMOSIS_LP_ASSET_PRECISION) < 0) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_Other, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Add Liquidity",
                 "Deposit %.6f %s and...",
                 atof(msg->lp_add.amount_in_max_b) / pow(10, OSMOSIS_PRECISION),
                 (!strcmp(msg->lp_add.denom_in_max_b, "uosmo"))
                     ? "OSMO"
                     : msg->lp_add.denom_in_max_b)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Add Liquidity",
                 "... %.6f %s?",
                 atof(msg->lp_add.amount_in_max_a) / pow(10, OSMOSIS_PRECISION),
                 (!strcmp(msg->lp_add.denom_in_max_a, "uosmo"))
                     ? "OSMO"
                     : msg->lp_add.denom_in_max_a)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Pool ID",
                 "%lld", msg->lp_add.pool_id)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other,
                 "Confirm Share Out Amount", "Receive %s GAMM-%lld shares?",
                 outsoamt, msg->lp_add.pool_id)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgLPAdd(
            msg->lp_add.pool_id, msg->lp_add.sender,
            msg->lp_add.share_out_amount, msg->lp_add.amount_in_max_a,
            msg->lp_add.denom_in_max_a, msg->lp_add.amount_in_max_b,
            msg->lp_add.denom_in_max_b)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include LP add message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_lp_remove) {
    /** Confirm required transaction parameters exist */
    if (!msg->lp_remove.has_sender || !msg->lp_remove.has_pool_id ||
        !msg->lp_remove.has_share_in_amount ||
        !msg->lp_remove.has_denom_out_min_a ||
        !msg->lp_remove.has_amount_out_min_a ||
        !msg->lp_remove.has_denom_out_min_b ||
        !msg->lp_remove.has_amount_out_min_b) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    /** Confirm transaction parameters on-screen */
    char insoamt[33] = {0};
    uint8_t outsoamt[34] = {0};
    strlcpy(insoamt, msg->lp_remove.share_in_amount,
            sizeof(msg->lp_remove.share_in_amount));

    if (base_to_precision(outsoamt, (uint8_t *)insoamt, sizeof(outsoamt),
                          strlen(insoamt), OSMOSIS_LP_ASSET_PRECISION) < 0) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_Other, NULL);
      layoutHome();
      return;
    }

    if (!confirm(
            ButtonRequestType_ButtonRequest_Other, "Remove Liquidity",
            "Withdraw %.6f %s and...",
            atof(msg->lp_remove.amount_out_min_b) / pow(10, OSMOSIS_PRECISION),
            (!strcmp(msg->lp_remove.denom_out_min_b, "uosmo"))
                ? "OSMO"
                : msg->lp_remove.denom_out_min_b)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(
            ButtonRequestType_ButtonRequest_Other, "Remove Liquidity",
            "... %.6f %s ?",
            atof(msg->lp_remove.amount_out_min_a) / pow(10, OSMOSIS_PRECISION),
            (!strcmp(msg->lp_remove.denom_out_min_a, "uosmo"))
                ? "OSMO"
                : msg->lp_remove.denom_out_min_a)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Pool ID",
                 "%lld", msg->lp_remove.pool_id)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Pool share amount",
                 "Redeem %s GAMM-%lld shares?", outsoamt,
                 msg->lp_remove.pool_id)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgLPRemove(
            msg->lp_remove.pool_id, msg->lp_remove.sender,
            msg->lp_remove.share_in_amount, msg->lp_remove.amount_out_min_a,
            msg->lp_remove.denom_out_min_a, msg->lp_remove.amount_out_min_b,
            msg->lp_remove.denom_out_min_b)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include rewards message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_redelegate) {
    /** Confirm required transaction parameters exist */
    if (!msg->redelegate.has_delegator_address ||
        !msg->redelegate.has_validator_src_address ||
        !msg->redelegate.has_validator_dst_address ||
        !msg->redelegate.has_amount) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }
    /** Confirm transaction parameters on-screen */

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Redelegate",
                 "Redelegate %.6f OSMO?",
                 atof(msg->send.amount) / pow(10, OSMOSIS_PRECISION))) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_osmosis_address("Delegator Address",
                                 msg->redelegate.delegator_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_osmosis_address("Validator Source Address",
                                 msg->redelegate.validator_src_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_osmosis_address("Validator Dest. Address",
                                 msg->redelegate.validator_dst_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgRedelegate(
            msg->redelegate.amount, msg->redelegate.delegator_address,
            msg->redelegate.validator_src_address,
            msg->redelegate.validator_dst_address, msg->redelegate.denom)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include redelegate message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_rewards) {
    /** Confirm required transaction parameters exist */
    if (!msg->rewards.has_delegator_address ||
        !msg->rewards.has_validator_address) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Claim Rewards",
                 "Claim all available rewards?")) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_osmosis_address("Confirm Delegator Address",
                                 msg->rewards.delegator_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm_osmosis_address("Confirm Validator Address",
                                 msg->rewards.validator_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgRewards(msg->rewards.delegator_address,
                                        msg->rewards.validator_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include rewards message in transaction");
      layoutHome();
      return;
    }
  } else if (msg->has_swap) {
    /** Confirm required transaction parameters exist */
    if (!msg->swap.has_sender ||
        !msg->swap.has_pool_id | !msg->swap.has_token_out_denom ||
        !msg->swap.has_token_in_denom || !msg->swap.has_token_in_amount ||
        !msg->swap.has_token_out_min_amount) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    /** Confirm transaction parameters on-screen */

    if (!confirm(
            ButtonRequestType_ButtonRequest_Other, "Swap",
            "Swap %.6f %s for at least %.6f %s?",
            atof(msg->swap.token_in_amount) / pow(10, OSMOSIS_PRECISION),
            msg->swap.token_in_denom,
            atof(msg->swap.token_out_min_amount) / pow(10, OSMOSIS_PRECISION),
            msg->swap.token_out_denom)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Pool ID",
                 "%lld", msg->swap.pool_id)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgSwap(
            msg->swap.pool_id, msg->swap.token_out_denom, msg->swap.sender,
            msg->swap.token_in_amount, msg->swap.token_in_denom,
            msg->swap.token_out_min_amount)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include swap message in transaction");
      layoutHome();
      return;
    }

  } else if (msg->has_ibc_transfer) {
    /** Confirm required transaction parameters exist */
    if (!msg->ibc_transfer.has_sender ||
        !msg->ibc_transfer.has_source_channel ||
        !msg->ibc_transfer.has_source_port ||
        !msg->ibc_transfer.has_revision_height ||
        !msg->ibc_transfer.has_revision_number ||
        !msg->ibc_transfer.has_denom) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }
    /** Confirm transaction parameters on-screen */

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "IBC Transfer",
                 "Transfer %.6f %s?",
                 atof(msg->ibc_transfer.amount) / pow(10, OSMOSIS_PRECISION),
                 msg->ibc_transfer.denom)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Dest. Addr",
                 "%s", msg->ibc_transfer.receiver)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other,
                 "Confirm Source Channel", "%s",
                 msg->ibc_transfer.source_channel)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Source Port",
                 "%s", msg->ibc_transfer.source_port)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other,
                 "Confirm Revision Height", "%s",
                 msg->ibc_transfer.revision_height)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other,
                 "Confirm Revision Number", "%s",
                 msg->ibc_transfer.revision_number)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgIBCTransfer(
            msg->ibc_transfer.amount, msg->ibc_transfer.sender,
            msg->ibc_transfer.receiver, msg->ibc_transfer.source_channel,
            msg->ibc_transfer.source_port, msg->ibc_transfer.revision_number,
            msg->ibc_transfer.revision_height, msg->ibc_transfer.denom)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include IBC transfer message in transaction");
      layoutHome();
      return;
    }
  } else {
    osmosis_signAbort();
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Invalid Osmosis message type"));
    layoutHome();
    return;
  }

  if (!osmosis_signingIsFinished()) {
    RESP_INIT(OsmosisMsgRequest);
    msg_write(MessageType_MessageType_OsmosisMsgRequest, resp);
    return;
  }

  if (sign_tx->has_memo && (strlen(sign_tx->memo) > 0)) {
    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmMemo, _("Memo"), "%s",
                 sign_tx->memo)) {
      osmosis_signAbort();
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
               "Sign this Osmosis transaction on %s? "
               "It includes a fee of %" PRIu32 " uOSMO and %" PRIu32 " gas.",
               sign_tx->chain_id, sign_tx->fee_amount, sign_tx->gas)) {
    osmosis_signAbort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
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
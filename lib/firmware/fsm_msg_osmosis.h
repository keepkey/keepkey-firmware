#include <math.h>
#include "keepkey/board/util.h" /* base_to_precision for osmosis_format_amount */
#define OSMOSIS_PRECISION 6
#define OSMOSIS_LP_ASSET_PRECISION 18

/* Render an Osmosis amount (host-supplied base-10 integer string) as a
 * fixed-precision decimal for the confirmation screen, without going through
 * float. The prior code did: float amount = atof(str); amount /= pow(10, PREC);
 * ... "%.6f", which loses precision past ~7 significant digits while the
 * signed JSON keeps the exact integer string (display-vs-signed divergence,
 * GH #438). This helper uses base_to_precision (integer-string decimal
 * insertion) so the rendered value is always faithful to the signed string. */
static void osmosis_format_amount(char* out, size_t out_len,
                                  const char* amount_str, const char* denom) {
  if (!out || out_len == 0) return;
  out[0] = '\0';
  const char* d = denom ? denom : "";

  if (!amount_str || amount_str[0] == '\0') {
    snprintf(out, out_len, "0 %s", d);
    return;
  }

  /* Only the native denom has an exponent this firmware knows. An IBC hash or
     a factory denom carries an exponent we cannot determine, so scaling it by
     10^6 would put a number on screen that is not the number being signed.
     Those are shown as the exact integer with the exact denom. */
  if (strcmp(d, "uosmo") != 0) {
    snprintf(out, out_len, "%s %s", amount_str, d);
    return;
  }

  const size_t amt_len = strlen(amount_str);
  char decimal_buf[80];
  if (amt_len > 64 ||
      base_to_precision((uint8_t*)decimal_buf, (const uint8_t*)amount_str,
                        (uint8_t)sizeof(decimal_buf), (uint8_t)amt_len,
                        OSMOSIS_PRECISION) != 0) {
    /* Cannot render faithfully: show the exact signed integer rather than a
       rounded or truncated decimal. */
    snprintf(out, out_len, "%s uosmo", amount_str);
    return;
  }
  snprintf(out, out_len, "%s OSMO", decimal_buf);
}

void fsm_msgOsmosisGetAddress(const OsmosisGetAddress* msg) {
  RESP_INIT(OsmosisAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  const CoinType* coin = fsm_getCoin(true, "Osmosis");
  if (!coin) {
    return;
  }
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  const char mainnet[] = "osmo";
  const char testnet[] = "tosmo";
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
  msg_write(MessageType_MessageType_OsmosisAddress, resp);
  layoutHome();
}

void fsm_msgOsmosisSignTx(const OsmosisSignTx* msg) {
  CHECK_INITIALIZED

  if (!msg->has_account_number || !msg->has_chain_id || !msg->has_fee_amount ||
      !msg->has_gas || !msg->has_sequence || !msg->has_msg_count ||
      msg->msg_count == 0 || !tendermint_validateSafeText(msg->chain_id)) {
    osmosis_signAbort();
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

/* A `sender` is the authority the message acts as. It is copied into the signed
   document verbatim and no LP, swap or IBC screen ever showed it, so the owner
   approved a document naming an account no screen mentioned. There is exactly
   one account this session can legitimately act as -- the one whose key signs
   -- so bind it rather than adding a screen to every flow. A mismatch could
   not produce a valid transaction anyway. */
static bool osmosis_validate_sender(bool has_value, const char* value) {
  return osmosis_validate_required_text(has_value, value) &&
         osmosis_address_is_signer(value);
}

void fsm_msgOsmosisMsgAck(const OsmosisMsgAck* msg) {
  /** Confirm transaction basics */
  CHECK_PARAM(osmosis_signingIsInited(), "Signing not in progress");

  const CoinType* coin = fsm_getCoin(true, "Osmosis");
  if (!coin) {
    return;
  }

  const OsmosisSignTx* sign_tx = osmosis_getOsmosisSignTx();

  /** Confirm required transaction parameters exist */
  if (msg->has_send) {
    if (!osmosis_validate_account_address(msg->send.has_to_address,
                                          msg->send.to_address) ||
        !osmosis_validate_amount(msg->send.has_amount, msg->send.amount) ||
        !osmosis_validate_required_text(msg->send.has_denom, msg->send.denom)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    const char* denom = msg->send.denom;
    char amount_str[128];
    osmosis_format_amount(amount_str, sizeof(amount_str), msg->send.amount,
                          denom);

    /** Confirm transaction parameters on screen */
    if (!confirm_transaction_output(
            ButtonRequestType_ButtonRequest_ConfirmOutput, amount_str,
            msg->send.to_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!osmosis_signTxUpdateMsgSend(msg->send.amount, msg->send.to_address,
                                     msg->send.denom)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Failed to include send message in transaction");
      layoutHome();
      return;
    }

  } else if (msg->has_delegate) {
    /** Confirm required transaction parameters exist */
    if (!osmosis_validate_account_address(msg->delegate.has_delegator_address,
                                          msg->delegate.delegator_address) ||
        !osmosis_validate_validator_address(msg->delegate.has_validator_address,
                                            msg->delegate.validator_address) ||
        !osmosis_validate_amount(msg->delegate.has_amount,
                                 msg->delegate.amount) ||
        !osmosis_validate_required_text(msg->delegate.has_denom,
                                        msg->delegate.denom)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    const char* denom = msg->delegate.denom;
    char amount_str[128];
    osmosis_format_amount(amount_str, sizeof(amount_str), msg->delegate.amount,
                          denom);

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

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Amount", "%s",
                 amount_str)) {
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
    if (!osmosis_validate_account_address(msg->undelegate.has_delegator_address,
                                          msg->undelegate.delegator_address) ||
        !osmosis_validate_validator_address(
            msg->undelegate.has_validator_address,
            msg->undelegate.validator_address) ||
        !osmosis_validate_amount(msg->undelegate.has_amount,
                                 msg->undelegate.amount) ||
        !osmosis_validate_required_text(msg->undelegate.has_denom,
                                        msg->undelegate.denom)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    const char* denom = msg->undelegate.denom;
    char amount_str[128];
    osmosis_format_amount(amount_str, sizeof(amount_str),
                          msg->undelegate.amount, denom);

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

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Amount", "%s",
                 amount_str)) {
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
    if (!osmosis_validate_sender(msg->lp_add.has_sender, msg->lp_add.sender) ||
        !msg->lp_add.has_pool_id ||
        !osmosis_validate_amount(msg->lp_add.has_share_out_amount,
                                 msg->lp_add.share_out_amount) ||
        !osmosis_validate_required_text(msg->lp_add.has_denom_in_max_a,
                                        msg->lp_add.denom_in_max_a) ||
        !osmosis_validate_amount(msg->lp_add.has_amount_in_max_a,
                                 msg->lp_add.amount_in_max_a) ||
        !osmosis_validate_required_text(msg->lp_add.has_denom_in_max_b,
                                        msg->lp_add.denom_in_max_b) ||
        !osmosis_validate_amount(msg->lp_add.has_amount_in_max_b,
                                 msg->lp_add.amount_in_max_b)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    char insoamt[33] = {0};
    uint8_t outsoamt[34] = {0};
    strlcpy(insoamt, msg->lp_add.share_out_amount,
            sizeof(msg->lp_add.share_out_amount));

    if (base_to_precision(outsoamt, (uint8_t*)insoamt, sizeof(outsoamt),
                          strlen(insoamt), OSMOSIS_LP_ASSET_PRECISION) < 0) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_Other, NULL);
      layoutHome();
      return;
    }

    const char* denom_in_max_b = msg->lp_add.denom_in_max_b;
    const char* denom_in_max_a = msg->lp_add.denom_in_max_a;
    char amt_b_str[128];
    osmosis_format_amount(amt_b_str, sizeof(amt_b_str),
                          msg->lp_add.amount_in_max_b, denom_in_max_b);
    char amt_a_str[128];
    osmosis_format_amount(amt_a_str, sizeof(amt_a_str),
                          msg->lp_add.amount_in_max_a, denom_in_max_a);

    /** Confirm transaction parameters on-screen */
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Add Liquidity",
                 "Deposit %s and...", amt_b_str)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Add Liquidity",
                 "... %s?", amt_a_str)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Pool ID",
                 "%" PRIu64, msg->lp_add.pool_id)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other,
                 "Confirm Share Out Amount",
                 "Receive %s GAMM-%" PRIu64 " shares?", outsoamt,
                 msg->lp_add.pool_id)) {
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
    if (!osmosis_validate_sender(msg->lp_remove.has_sender,
                                 msg->lp_remove.sender) ||
        !msg->lp_remove.has_pool_id ||
        !osmosis_validate_amount(msg->lp_remove.has_share_in_amount,
                                 msg->lp_remove.share_in_amount) ||
        !osmosis_validate_required_text(msg->lp_remove.has_denom_out_min_a,
                                        msg->lp_remove.denom_out_min_a) ||
        !osmosis_validate_amount(msg->lp_remove.has_amount_out_min_a,
                                 msg->lp_remove.amount_out_min_a) ||
        !osmosis_validate_required_text(msg->lp_remove.has_denom_out_min_b,
                                        msg->lp_remove.denom_out_min_b) ||
        !osmosis_validate_amount(msg->lp_remove.has_amount_out_min_b,
                                 msg->lp_remove.amount_out_min_b)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    char insoamt[33] = {0};
    uint8_t outsoamt[34] = {0};
    strlcpy(insoamt, msg->lp_remove.share_in_amount,
            sizeof(msg->lp_remove.share_in_amount));

    if (base_to_precision(outsoamt, (uint8_t*)insoamt, sizeof(outsoamt),
                          strlen(insoamt), OSMOSIS_LP_ASSET_PRECISION) < 0) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_Other, NULL);
      layoutHome();
      return;
    }

    const char* denom_out_min_b = msg->lp_remove.denom_out_min_b;
    const char* denom_out_min_a = msg->lp_remove.denom_out_min_a;
    char out_b_str[128];
    osmosis_format_amount(out_b_str, sizeof(out_b_str),
                          msg->lp_remove.amount_out_min_b, denom_out_min_b);
    char out_a_str[128];
    osmosis_format_amount(out_a_str, sizeof(out_a_str),
                          msg->lp_remove.amount_out_min_a, denom_out_min_a);

    /** Confirm transaction parameters on-screen */
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Remove Liquidity",
                 "Withdraw %s and...", out_b_str)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Remove Liquidity",
                 "... %s ?", out_a_str)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Pool ID",
                 "%" PRIu64, msg->lp_remove.pool_id)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Pool share amount",
                 "Redeem %s GAMM-%" PRIu64 " shares?", outsoamt,
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
    if (!osmosis_validate_account_address(msg->redelegate.has_delegator_address,
                                          msg->redelegate.delegator_address) ||
        !osmosis_validate_validator_address(
            msg->redelegate.has_validator_src_address,
            msg->redelegate.validator_src_address) ||
        !osmosis_validate_validator_address(
            msg->redelegate.has_validator_dst_address,
            msg->redelegate.validator_dst_address) ||
        !osmosis_validate_amount(msg->redelegate.has_amount,
                                 msg->redelegate.amount) ||
        !osmosis_validate_required_text(msg->redelegate.has_denom,
                                        msg->redelegate.denom)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    char redelegate_str[128];
    osmosis_format_amount(redelegate_str, sizeof(redelegate_str),
                          msg->redelegate.amount, msg->redelegate.denom);

    /** Confirm transaction parameters on-screen */
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Redelegate",
                 "Redelegate %s?", redelegate_str)) {
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
    if (!osmosis_validate_account_address(msg->rewards.has_delegator_address,
                                          msg->rewards.delegator_address) ||
        !osmosis_validate_validator_address(msg->rewards.has_validator_address,
                                            msg->rewards.validator_address)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    /** Confirm transaction parameters on-screen */
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
    if (!osmosis_validate_sender(msg->swap.has_sender, msg->swap.sender) ||
        !msg->swap.has_pool_id ||
        !osmosis_validate_required_text(msg->swap.has_token_out_denom,
                                        msg->swap.token_out_denom) ||
        !osmosis_validate_required_text(msg->swap.has_token_in_denom,
                                        msg->swap.token_in_denom) ||
        !osmosis_validate_amount(msg->swap.has_token_in_amount,
                                 msg->swap.token_in_amount) ||
        !osmosis_validate_amount(msg->swap.has_token_out_min_amount,
                                 msg->swap.token_out_min_amount)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    const char* token_in_denom = msg->swap.token_in_denom;
    const char* token_out_denom = msg->swap.token_out_denom;
    char swap_in_str[128];
    osmosis_format_amount(swap_in_str, sizeof(swap_in_str),
                          msg->swap.token_in_amount, token_in_denom);
    char swap_out_str[128];
    osmosis_format_amount(swap_out_str, sizeof(swap_out_str),
                          msg->swap.token_out_min_amount, token_out_denom);

    /** Confirm transaction parameters on-screen */
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Swap",
                 "Swap %s for at least %s?", swap_in_str, swap_out_str)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    if (!confirm(ButtonRequestType_ButtonRequest_Other, "Confirm Pool ID",
                 "%" PRIu64, msg->swap.pool_id)) {
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
    /* The receiver has to be well-formed bech32 BEFORE any screen opens.
       The serializer refuses a malformed one, but it runs after every IBC
       approval has already been taken, so the owner approved a transfer
       that was then rejected. Its HRP belongs to the counterparty chain,
       so only well-formedness can be checked here -- that is exactly what
       the serializer checks, moved ahead of the confirmations. */
    if (!osmosis_validate_sender(msg->ibc_transfer.has_sender,
                                 msg->ibc_transfer.sender) ||
        !osmosis_validate_required_text(msg->ibc_transfer.has_receiver,
                                        msg->ibc_transfer.receiver) ||
        !osmosis_validate_required_text(msg->ibc_transfer.has_source_channel,
                                        msg->ibc_transfer.source_channel) ||
        !osmosis_validate_required_text(msg->ibc_transfer.has_source_port,
                                        msg->ibc_transfer.source_port) ||
        !tendermint_bech32IsWellFormed(msg->ibc_transfer.receiver) ||
        !osmosis_validate_amount(msg->ibc_transfer.has_revision_height,
                                 msg->ibc_transfer.revision_height) ||
        !osmosis_validate_amount(msg->ibc_transfer.has_revision_number,
                                 msg->ibc_transfer.revision_number) ||
        !osmosis_validate_required_text(msg->ibc_transfer.has_denom,
                                        msg->ibc_transfer.denom) ||
        !osmosis_validate_amount(msg->ibc_transfer.has_amount,
                                 msg->ibc_transfer.amount)) {
      osmosis_signAbort();
      fsm_sendFailure(FailureType_Failure_FirmwareError,
                      _("Message is missing required parameters"));
      layoutHome();
      return;
    }

    const char* denom = msg->ibc_transfer.denom;
    char ibc_amount_str[128];
    osmosis_format_amount(ibc_amount_str, sizeof(ibc_amount_str),
                          msg->ibc_transfer.amount, denom);

    /** Confirm transaction parameters on-screen */
    if (!confirm(ButtonRequestType_ButtonRequest_Other, "IBC Transfer",
                 "Transfer %s?", ibc_amount_str)) {
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
    if (!confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmMemo, _("Memo"),
                       (const uint8_t*)sign_tx->memo, strlen(sign_tx->memo))) {
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

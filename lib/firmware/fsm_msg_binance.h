
void fsm_msgBinanceGetAddress(const BinanceGetAddress* msg) {
  RESP_INIT(BinanceAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  const char* coin_name = "Binance";
  const CoinType* coin = fsm_getCoin(true, coin_name);
  if (!coin) {
    return;
  }
  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) {
    return;
  }

  hdnode_fill_public_key(node);

  if (!tendermint_getAddress(node, "bnb", resp->address)) {
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
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }
    }

    if (!confirm_ethereum_address(node_str, resp->address)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "Show address cancelled");
      layoutHome();
      return;
    }
  }

  resp->has_address = true;

  layoutHome();
  msg_write(MessageType_MessageType_BinanceAddress, resp);
}

void fsm_msgBinanceSignTx(const BinanceSignTx* msg) {
  CHECK_INITIALIZED
  CHECK_PIN

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) {
    return;
  }

  hdnode_fill_public_key(node);

  RESP_INIT(BinanceTxRequest);

  if (!binance_signTxInit(node, msg)) {
    binance_signAbort();
    fsm_sendFailure(FailureType_Failure_FirmwareError,
                    _("Failed to initialize transaction signing"));
    layoutHome();
    return;
  }

  layoutHome();
  msg_write(MessageType_MessageType_BinanceTxRequest, resp);
}

static void binance_response(void);

void fsm_msgBinanceTransferMsg(const BinanceTransferMsg* msg) {
  CHECK_PARAM(binance_signingIsInited(), "Signing not in progress?");
  if (!binance_validateTransfer(msg)) {
    binance_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Malformed BinanceTransferMsg");
    layoutHome();
    return;
  }

  const CoinType* coin = fsm_getCoin(true, "Binance");
  if (!coin) {
    binance_signAbort();
    layoutHome();
    return;
  }

  switch (msg->outputs[0].address_type) {
    case OutputAddressType_TRANSFER:
    default: {
      /* BinanceCoin.denom is max_size:32 (messages-binance.options), i.e. 31
       * visible chars + NUL, so ' ' + 31 + NUL = 34. The pre-fix code passed
       * strlen(denom)+2 as the snprintf SIZE against a 14-byte buffer, which
       * for a 31-char denom is 33 and overflowed the stack by up to 19 bytes
       * (GH #430). Both branches resized; this one additionally CHECKS the
       * snprintf and bn_format_uint64 results and fails closed, so a truncated
       * or unformattable amount can never reach the confirmation screen. */
      char amount_str[64];
      char denom_str[BINANCE_MAX_DENOM_LEN + 2];
      const int denom_len = snprintf(denom_str, sizeof(denom_str), " %s",
                                     msg->outputs[0].coins[0].denom);
      if (denom_len <= 0 || (size_t)denom_len >= sizeof(denom_str) ||
          !bn_format_uint64((uint64_t)msg->outputs[0].coins[0].amount, NULL,
                            denom_str, 8, 0, false, amount_str,
                            sizeof(amount_str))) {
        binance_signAbort();
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        "Invalid Binance transfer amount");
        layoutHome();
        return;
      }
      if (!confirm_transaction_output(
              ButtonRequestType_ButtonRequest_ConfirmOutput, amount_str,
              msg->outputs[0].address)) {
        binance_signAbort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        layoutHome();
        return;
      }
      break;
    }
  }

  if (!binance_signTxUpdateTransfer(msg)) {
    binance_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Failed to include transfer message in transaction");
    layoutHome();
    return;
  }

  binance_response();
}

static void binance_response(void) {
  if (!binance_signingIsFinished()) {
    RESP_INIT(BinanceTxRequest);
    msg_write(MessageType_MessageType_BinanceTxRequest, resp);
    return;
  }

  const CoinType* coin = fsm_getCoin(true, "Binance");
  if (!coin) {
    binance_signAbort();
    layoutHome();
    return;
  }

  const BinanceSignTx* sign_tx = binance_getBinanceSignTx();

  if (sign_tx->has_memo &&
      !confirm_bytes(ButtonRequestType_ButtonRequest_ConfirmMemo, _("Memo"),
                     (const uint8_t*)sign_tx->memo, strlen(sign_tx->memo))) {
    binance_signAbort();
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
               "Sign this Binance transaction on %s?", sign_tx->chain_id)) {
    binance_signAbort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  RESP_INIT(BinanceSignedTx);

  if (!binance_signTxFinalize(resp->public_key.bytes, resp->signature.bytes)) {
    binance_signAbort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Failed to finalize signature");
    layoutHome();
    return;
  }

  resp->public_key.size = 33;
  resp->has_public_key = true;
  resp->signature.size = 64;
  resp->has_signature = true;
  binance_signAbort();
  layoutHome();
  msg_write(MessageType_MessageType_BinanceSignedTx, resp);
}

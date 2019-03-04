

static int process_ethereum_xfer(const CoinType *coin, EthereumSignTx *msg)
{
    // Precheck: For TRANSFER, 'to' fields must not be already loaded.
    if (msg->has_to || msg->to.size || strlen((char *)msg->to.bytes) != 0 ||
        msg->has_token_to || msg->token_to.size || strlen((char*)msg->token_to.bytes) != 0)
        return TXOUT_COMPILE_ERROR;

    char node_str[NODE_STRING_LENGTH];
    if (!bip32_node_to_string(node_str, sizeof(node_str), coin, msg->to_address_n,
                              msg->to_address_n_count, /*whole_account=*/false,
                              /*allow_change=*/false, /*show_addridx=*/false))
        return TXOUT_COMPILE_ERROR;

    bool *has_to;
    size_t *to_size;
    uint8_t *to_bytes;
    const uint8_t *value_bytes;
    const size_t *value_size;
    const TokenType *token;

    if (!coin->has_forkid)
        return TXOUT_COMPILE_ERROR;

    const uint32_t chain_id = coin->forkid;
    if (ethereum_isNonStandardERC20(msg)) {
        has_to = &msg->has_token_to;
        to_size = &msg->token_to.size;
        to_bytes = msg->token_to.bytes;
        value_bytes = msg->token_value.bytes;
        value_size = &msg->token_value.size;

        // Check that the ticker gives a unique lookup. If not, we can't
        // reliably do the lookup this way, and must abort.
        if (!tokenByTicker(chain_id, msg->token_shortcut, &token))
            return TXOUT_COMPILE_ERROR;
    } else {
        has_to = &msg->has_to;
        to_size = &msg->to.size;
        to_bytes = msg->to.bytes;
        value_bytes = msg->value.bytes;
        value_size = &msg->value.size;
        token = NULL;
    }

    bignum256 value;
    bn_from_bytes(value_bytes, *value_size, &value);

    char amount_str[128+sizeof(msg->token_shortcut)+3];
    ethereumFormatAmount(&value, token, chain_id, amount_str, sizeof(amount_str));

    if (!confirm_transfer_output(ButtonRequestType_ButtonRequest_ConfirmTransferToAccount,
                                 amount_str, node_str))
        return TXOUT_CANCEL;

    const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->to_address_n, msg->to_address_n_count, NULL);
    if (!node)
        return TXOUT_COMPILE_ERROR;

    if (!hdnode_get_ethereum_pubkeyhash(node, to_bytes))
        return TXOUT_COMPILE_ERROR;

    *has_to = true;
    *to_size = 20;

    memset((void *)node, 0, sizeof(HDNode));
    return TXOUT_OK;
}

static int process_ethereum_msg(EthereumSignTx *msg, bool *confirm_ptr)
{
    int ret_result = TXOUT_COMPILE_ERROR;
    const CoinType *coin = fsm_getCoin(true, ETHEREUM);

    if(coin != NULL)
    {
        switch(msg->address_type)
        {
            case OutputAddressType_EXCHANGE:
            {
                /*prep for exchange type transaction*/
                HDNode *root_node = fsm_getDerivedNode(SECP256K1_NAME, 0, 0, NULL); /* root node */
                ret_result = run_policy_compile_output(coin, root_node, (void *)msg, (void *)NULL, true);
                if(ret_result < TXOUT_OK) {
                    memset((void *)root_node, 0, sizeof(HDNode));
                }
                *confirm_ptr = false;
                break;
            }
            case OutputAddressType_TRANSFER:
            {
                /*prep transfer type transaction*/
                ret_result = process_ethereum_xfer(coin, msg);
                *confirm_ptr = false;
                break;
            }
            default:
                ret_result = TXOUT_OK;
                break;
        }
    }
    return(ret_result);
}

void fsm_msgEthereumSignTx(EthereumSignTx *msg)
{
	CHECK_INITIALIZED

	CHECK_PIN_TXSIGN

	bool needs_confirm = true;
	int msg_result = process_ethereum_msg(msg, &needs_confirm);

	if (msg_result < TXOUT_OK) {
		ethereum_signing_abort();
		send_fsm_co_error_message(msg_result);
		layoutHome();
		return;
	}

	const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count, NULL);
	if (!node) return;

	ethereum_signing_init(msg, node, needs_confirm);
}

void fsm_msgEthereumTxAck(EthereumTxAck *msg)
{
	ethereum_signing_txack(msg);
}

void fsm_msgEthereumGetAddress(EthereumGetAddress *msg)
{
	RESP_INIT(EthereumAddress);

	CHECK_INITIALIZED

	CHECK_PIN

	const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count, NULL);
	if (!node) return;

	resp->address.size = 20;

	if (!hdnode_get_ethereum_pubkeyhash(node, resp->address.bytes))
		return;

	const CoinType *coin = NULL;
	bool rskip60 = false;
	uint32_t chain_id = 0;

	if (msg->address_n_count == 5) {
		coin = coinBySlip44(msg->address_n[1]);
		uint32_t slip44 = msg->address_n[1] & 0x7fffffff;
		// constants from trezor-common/defs/ethereum/networks.json
		switch (slip44) {
			case 137: rskip60 = true; chain_id = 30; break;
			case 37310: rskip60 = true; chain_id = 31; break;
		}
	}

	char address[43] = { '0', 'x' };
	ethereum_address_checksum(resp->address.bytes, address + 2, rskip60, chain_id);

	resp->has_address_str = true;
	strlcpy(resp->address_str, address, sizeof(resp->address_str));

	if (msg->has_show_display && msg->show_display) {
		char node_str[NODE_STRING_LENGTH];
		if (!(coin && isEthereumLike(coin->coin_name) &&
		      bip32_node_to_string(node_str, sizeof(node_str), coin,
		                           msg->address_n,
		                           msg->address_n_count,
		                           /*whole_account=*/false,
		                           /*allow_change=*/false,
		                           /*show_addridx=*/false)) &&
		    !bip32_path_to_string(node_str, sizeof(node_str),
		                          msg->address_n, msg->address_n_count)) {
			memset(node_str, 0, sizeof(node_str));
		}

		if (!confirm_ethereum_address(node_str, address)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, _("Show address cancelled"));
			layoutHome();
			return;
		}
	}

	msg_write(MessageType_MessageType_EthereumAddress, resp);
	layoutHome();
}

void fsm_msgEthereumSignMessage(EthereumSignMessage *msg)
{
	RESP_INIT(EthereumMessageSignature);

	CHECK_INITIALIZED

	if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _("Sign Message"),
	             "%s", msg->message.bytes)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		layoutHome();
		return;
	}

	CHECK_PIN

	const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count, NULL);
	if (!node) return;

	ethereum_message_sign(msg, node, resp);
	layoutHome();
}

void fsm_msgEthereumVerifyMessage(const EthereumVerifyMessage *msg)
{
	CHECK_PARAM(msg->has_address, _("No address provided"));
	CHECK_PARAM(msg->has_message, _("No message provided"));

	if (ethereum_message_verify(msg) != 0) {
		fsm_sendFailure(FailureType_Failure_SyntaxError, _("Invalid signature"));
		return;
	}

	char address[43] = { '0', 'x' };
	ethereum_address_checksum(msg->address.bytes, address + 2, false, 0);
	if (!confirm_address(_("Confirm Signer"), address)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		layoutHome();
		return;
	}
	if (!confirm(ButtonRequestType_ButtonRequest_Other, _("Message Verified"), "%s",
	             msg->message.bytes)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		layoutHome();
		return;
	}
	fsm_sendSuccess(_("Message verified"));

	layoutHome();
}

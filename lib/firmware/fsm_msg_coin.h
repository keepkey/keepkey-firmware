void fsm_msgGetPublicKey(GetPublicKey *msg)
{
	RESP_INIT(PublicKey);

	CHECK_INITIALIZED

	CHECK_PIN

	InputScriptType script_type = msg->has_script_type ? msg->script_type : InputScriptType_SPENDADDRESS;

	const CoinType *coin = fsm_getCoin(msg->has_coin_name, msg->coin_name);
	if (!coin) return;

	const char *curve = coin->curve_name;
	if (msg->has_ecdsa_curve_name) {
		curve = msg->ecdsa_curve_name;
	}
	uint32_t fingerprint;
	HDNode *node = fsm_getDerivedNode(curve, msg->address_n, msg->address_n_count, &fingerprint);
	if (!node) return;
	hdnode_fill_public_key(node);

	resp->node.depth = node->depth;
	resp->node.fingerprint = fingerprint;
	resp->node.child_num = node->child_num;
	resp->node.chain_code.size = 32;
	memcpy(resp->node.chain_code.bytes, node->chain_code, 32);
	resp->node.has_private_key = false;
	resp->node.has_public_key = true;
	resp->node.public_key.size = 33;
	memcpy(resp->node.public_key.bytes, node->public_key, 33);
	if (node->public_key[0] == 1) {
		/* ed25519 public key */
		resp->node.public_key.bytes[0] = 0;
	}
	resp->has_xpub = true;

	if (coin->xpub_magic && script_type == InputScriptType_SPENDADDRESS) {
		hdnode_serialize_public(node, fingerprint, coin->xpub_magic, resp->xpub, sizeof(resp->xpub));
	} else
	if (coin->has_segwit && coin->xpub_magic_segwit_p2sh && script_type == InputScriptType_SPENDP2SHWITNESS) {
		hdnode_serialize_public(node, fingerprint, coin->xpub_magic_segwit_p2sh, resp->xpub, sizeof(resp->xpub));
	} else
	if (coin->has_segwit && coin->xpub_magic_segwit_native && script_type == InputScriptType_SPENDWITNESS) {
		hdnode_serialize_public(node, fingerprint, coin->xpub_magic_segwit_native, resp->xpub, sizeof(resp->xpub));
	} else {
		fsm_sendFailure(FailureType_Failure_Other, _("Invalid combination of coin and script_type"));
		layoutHome();
		return;
	}

	if (msg->has_show_display && msg->show_display)
	{
		char node_str[NODE_STRING_LENGTH];
		if (!bip32_node_to_string(node_str, sizeof(node_str), coin,
		                          msg->address_n,
		                          msg->address_n_count,
		                          /*whole_account=*/true,
		                          /*allow_change=*/false,
		                          /*show_addridx=*/false) &&
		    !bip32_path_to_string(node_str, sizeof(node_str),
		                          msg->address_n, msg->address_n_count)) {
			memset(node_str, 0, sizeof(node_str));
		}

		if (!confirm_xpub(node_str, resp->xpub))
		{
			fsm_sendFailure(FailureType_Failure_ActionCancelled, "Show extended public key cancelled");
			layoutHome();
			return;
		}
	}

	msg_write(MessageType_MessageType_PublicKey, resp);
	layoutHome();

	if (node)
		memzero(node, sizeof(node));
}

void fsm_msgSignTx(SignTx *msg)
{
	CHECK_INITIALIZED

	CHECK_PARAM(msg->inputs_count > 0, _("Transaction must have at least one input"));
	CHECK_PARAM(msg->outputs_count > 0, _("Transaction must have at least one output"));
	CHECK_PARAM(msg->inputs_count + msg->outputs_count >= msg->inputs_count, _("Value overflow"));

	CHECK_PIN_TXSIGN

	const CoinType *coin = fsm_getCoin(msg->has_coin_name, msg->coin_name);
	if(!coin) { return; }
	const HDNode *node = fsm_getDerivedNode(coin->curve_name, 0, 0, NULL);
	if(!node) { return; }

    layout_simple_message("Preparing Transaction...");

	signing_init(msg, coin, node);
}

void fsm_msgTxAck(TxAck *msg)
{
	CHECK_PARAM(msg->has_tx, _("No transaction provided"));

	signing_txack(&(msg->tx));
}

// NOTE: there is a very similar copy of this function in coins.c
//       PLEASE keep both copies in sync.
static bool path_mismatched(const CoinType *coin, const GetAddress *msg)
{
	bool mismatch = false;

	// m : no path
	if (msg->address_n_count == 0) {
		return false;
	}

	// m/44' : BIP44 Legacy
	// m / purpose' / bip44_account_path' / account' / change / address_index
	if (msg->address_n[0] == (0x80000000 + 44)) {
		mismatch |= (msg->script_type != InputScriptType_SPENDADDRESS);
		mismatch |= (msg->address_n_count != 5);
		mismatch |= (msg->address_n[1] != coin->bip44_account_path);
		mismatch |= (msg->address_n[2] & 0x80000000) == 0;
		mismatch |= (msg->address_n[3] & 0x80000000) == 0x80000000;
		mismatch |= (msg->address_n[4] & 0x80000000) == 0x80000000;
		return mismatch;
	}

	// m/45' - BIP45 Copay Abandoned Multisig P2SH
	// m / purpose' / cosigner_index / change / address_index
	if (msg->address_n[0] == (0x80000000 + 45)) {
		mismatch |= (msg->script_type != InputScriptType_SPENDMULTISIG);
		mismatch |= (msg->address_n_count != 4);
		mismatch |= (msg->address_n[1] & 0x80000000) == 0x80000000;
		mismatch |= (msg->address_n[2] & 0x80000000) == 0x80000000;
		mismatch |= (msg->address_n[3] & 0x80000000) == 0x80000000;
		return mismatch;
	}

	// m/48' - BIP48 Copay Multisig P2SH
	// m / purpose' / bip44_account_path' / account' / change / address_index
	if (msg->address_n[0] == (0x80000000 + 48)) {
		mismatch |= (msg->script_type != InputScriptType_SPENDMULTISIG);
		mismatch |= (msg->address_n_count != 5);
		mismatch |= (msg->address_n[1] != coin->bip44_account_path);
		mismatch |= (msg->address_n[2] & 0x80000000) == 0;
		mismatch |= (msg->address_n[3] & 0x80000000) == 0x80000000;
		mismatch |= (msg->address_n[4] & 0x80000000) == 0x80000000;
		return mismatch;
	}

	// m/49' : BIP49 SegWit
	// m / purpose' / bip44_account_path' / account' / change / address_index
	if (msg->address_n[0] == (0x80000000 + 49)) {
		mismatch |= (msg->script_type != InputScriptType_SPENDP2SHWITNESS);
		mismatch |= !coin->has_segwit || !coin->segwit;
		mismatch |= !coin->has_address_type_p2sh;
		mismatch |= (msg->address_n_count != 5);
		mismatch |= (msg->address_n[1] != coin->bip44_account_path);
		mismatch |= (msg->address_n[2] & 0x80000000) == 0;
		mismatch |= (msg->address_n[3] & 0x80000000) == 0x80000000;
		mismatch |= (msg->address_n[4] & 0x80000000) == 0x80000000;
		return mismatch;
	}

	// m/84' : BIP84 Native SegWit
	// m / purpose' / bip44_account_path' / account' / change / address_index
	if (msg->address_n[0] == (0x80000000 + 84)) {
		mismatch |= (msg->script_type != InputScriptType_SPENDWITNESS);
		mismatch |= !coin->has_segwit || !coin->segwit;
		mismatch |= !coin->has_bech32_prefix;
		mismatch |= (msg->address_n_count != 5);
		mismatch |= (msg->address_n[1] != coin->bip44_account_path);
		mismatch |= (msg->address_n[2] & 0x80000000) == 0;
		mismatch |= (msg->address_n[3] & 0x80000000) == 0x80000000;
		mismatch |= (msg->address_n[4] & 0x80000000) == 0x80000000;
		return mismatch;
	}

	return false;
}

void fsm_msgGetAddress(GetAddress *msg)
{
	RESP_INIT(Address);

	CHECK_INITIALIZED

	CHECK_PIN

	const CoinType *coin = fsm_getCoin(msg->has_coin_name, msg->coin_name);
	if (!coin) return;
	HDNode *node = fsm_getDerivedNode(coin->curve_name, msg->address_n, msg->address_n_count, NULL);
	if (!node) return;
	hdnode_fill_public_key(node);

	char address[MAX_ADDR_SIZE];
	if (msg->has_multisig) {  // use progress bar only for multisig
		animating_progress_handler(_("Computing address"), 0);
	}
	if (!compute_address(coin, msg->script_type, node, msg->has_multisig, &msg->multisig, address)) {
		fsm_sendFailure(FailureType_Failure_Other, _("Can't encode address"));
		layoutHome();
		return;
	}

	if (msg->has_show_display && msg->show_display) {
		char node_str[NODE_STRING_LENGTH];
		if (msg->has_multisig) {
			snprintf(node_str, sizeof(node_str), "Multisig (%" PRIu32 " of %" PRIu32 ")",
			         msg->multisig.m, (uint32_t)msg->multisig.pubkeys_count);
		} else {
			if (!bip32_node_to_string(node_str, sizeof(node_str), coin, msg->address_n,
			                          msg->address_n_count, /*whole_account=*/false,
			                          /*allow_change=*/false, /*show_addridx=*/true) &&
			    !bip32_path_to_string(node_str, sizeof(node_str),
			                          msg->address_n, msg->address_n_count)) {
				memset(node_str, 0, sizeof(node_str));
			}
		}

		bool mismatch = path_mismatched(coin, msg);

		if (mismatch) {
			if (!confirm(ButtonRequestType_ButtonRequest_Other, "WARNING", "Wrong address path for selected coin. Continue at your own risk!")) {
				fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
				layoutHome();
				return;
			}
		}

		size_t prefix_len = coin->has_cashaddr_prefix
		    ? strlen(coin->cashaddr_prefix) + 1
		    : 0;

		if(!confirm_address(node_str, address + prefix_len))
		{
			fsm_sendFailure(FailureType_Failure_ActionCancelled, "Show address cancelled");
			layoutHome();
			return;
		}
	}

	strlcpy(resp->address, address, sizeof(resp->address));
	msg_write(MessageType_MessageType_Address, resp);
	layoutHome();
}

void fsm_msgSignMessage(SignMessage *msg)
{
	RESP_INIT(MessageSignature);

	CHECK_INITIALIZED

	if (!confirm(ButtonRequestType_ButtonRequest_SignMessage, "Sign Message", "%s",
	             (char *)msg->message.bytes))
	{
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "Sign message cancelled");
		layoutHome();
		return;
	}

	CHECK_PIN

	const CoinType *coin = fsm_getCoin(msg->has_coin_name, msg->coin_name);
	if (!coin) return;
	HDNode *node = fsm_getDerivedNode(coin->curve_name, msg->address_n, msg->address_n_count, NULL);
	if (!node) return;

	animating_progress_handler(_("Signing"), 0);
	if (cryptoMessageSign(coin, node, msg->script_type, msg->message.bytes, msg->message.size, resp->signature.bytes) == 0) {
		resp->has_address = true;
		hdnode_fill_public_key(node);
		if (!compute_address(coin, msg->script_type, node, false, NULL, resp->address)) {
			fsm_sendFailure(FailureType_Failure_Other, _("Error computing address"));
			layoutHome();
			return;
		}
		resp->has_signature = true;
		resp->signature.size = 65;
		msg_write(MessageType_MessageType_MessageSignature, resp);
	} else {
		fsm_sendFailure(FailureType_Failure_Other, _("Error signing message"));
	}
	layoutHome();
}

void fsm_msgVerifyMessage(VerifyMessage *msg)
{
	CHECK_PARAM(msg->has_address, _("No address provided"));
	CHECK_PARAM(msg->has_message, _("No message provided"));

	const CoinType *coin = fsm_getCoin(msg->has_coin_name, msg->coin_name);
	if (!coin) return;
	layout_simple_message("Verifying Message...");

	if (msg->signature.size == 65 && cryptoMessageVerify(coin, msg->message.bytes, msg->message.size, msg->address, msg->signature.bytes) == 0) {
		if (!confirm_address("Confirm Signer", msg->address)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
			layoutHome();
			return;
		}
		if (!review(ButtonRequestType_ButtonRequest_Other, "Message Verified", "%s",
		            (char *)msg->message.bytes)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, _("Action cancelled by user"));
			layoutHome();
			return;
		}
		fsm_sendSuccess("Message verified");
	} else {
		fsm_sendFailure(FailureType_Failure_InvalidSignature, _("Invalid signature"));
	}
	layoutHome();
}

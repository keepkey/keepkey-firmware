void fsm_msgGetPublicKey(GetPublicKey *msg)
{
    RESP_INIT(PublicKey);

    if (!storage_isInitialized())
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
        return;
    }

    if(!pin_protect_cached())
    {
        go_home();
        return;
    }

    const char *curve = SECP256K1_NAME;
    if (msg->has_ecdsa_curve_name) {
        curve = msg->ecdsa_curve_name;
    }
    uint32_t fingerprint;
    HDNode *node;
    if (msg->address_n_count == 0) {
        /* get master node */
        fingerprint = 0;
        node = fsm_getDerivedNode(curve, msg->address_n, 0);
    } else {
        /* get parent node */
        node = fsm_getDerivedNode(curve, msg->address_n, msg->address_n_count - 1);
        if (!node) return;
        fingerprint = hdnode_fingerprint(node);
        /* get child */
        hdnode_private_ckd(node, msg->address_n[msg->address_n_count - 1]);
    }
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
    hdnode_serialize_public(node, fingerprint, 76067358 /* FIXME: coin->xpub_magic */, resp->xpub, sizeof(resp->xpub));

    if (msg->has_show_display && msg->show_display)
    {
        const CoinType *coin = msg->address_n_count > 2 &&
                               msg->address_n[0] == (0x80000000 | 44)
             ? coinBySlip44(msg->address_n[1])
             : 0;

        char node_str[NODE_STRING_LENGTH];
        if (!coin || !bip44_node_to_string(coin, node_str, msg->address_n,
                                           msg->address_n_count)) {
            memset(node_str, 0, sizeof(node_str));
        }

        if (!confirm_xpub(node_str, resp->xpub))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Show extended public key cancelled");
            go_home();
            return;
        }
    }

    msg_write(MessageType_MessageType_PublicKey, resp);
    go_home();

    if (node)
      memzero(node, sizeof(node));
}

void fsm_msgSignTx(SignTx *msg)
{

    if (!storage_isInitialized())
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
        return;
    }

    if(msg->inputs_count < 1)
    {
        fsm_sendFailure(FailureType_Failure_Other,
                        "Transaction must have at least one input");
        go_home();
        return;
    }

    if(msg->outputs_count < 1)
    {
        fsm_sendFailure(FailureType_Failure_Other,
                        "Transaction must have at least one output");
        go_home();
        return;
    }

    if(!pin_protect("Enter Current PIN"))
    {
        go_home();
        return;
    }

    const CoinType *coin = fsm_getCoin(msg->coin_name);

    if(!coin) { return; }

    /* master node */
    const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, 0, 0);

    if(!node) { return; }

    layout_simple_message("Preparing Transaction...");

    signing_init(msg->inputs_count, msg->outputs_count, coin, node,
                 msg->has_version ? msg->version : 1,
                 msg->has_lock_time ? msg->lock_time : 0);
}

void fsm_msgTxAck(TxAck *msg)
{
    if(msg->has_tx)
    {
        signing_txack(&(msg->tx));
    }
    else
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No transaction provided");
    }
}

void fsm_msgGetAddress(GetAddress *msg)
{
    RESP_INIT(Address);

    if (!storage_isInitialized())
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
        return;
    }

    if(!pin_protect_cached())
    {
        go_home();
        return;
    }

    const CoinType *coin = fsm_getCoin(msg->coin_name);

    if(!coin) { return; }

    HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count);

    if(!node) { return; }
    hdnode_fill_public_key(node);

    if(msg->has_multisig)
    {

        if(cryptoMultisigPubkeyIndex(&(msg->multisig), node->public_key) < 0)
        {
            fsm_sendFailure(FailureType_Failure_Other,
                            "Pubkey not found in multisig script");
            go_home();
            return;
        }

        uint8_t buf[32];

        if(compile_script_multisig_hash(&(msg->multisig), buf) == 0)
        {
            fsm_sendFailure(FailureType_Failure_Other, "Invalid multisig script");
            go_home();
            return;
        }

        ripemd160(buf, 32, buf + 1);
        buf[0] = coin->address_type_p2sh; // multisig cointype
#if 0
        base58_encode_check(buf, 21, coin->curve->hasher_base58, resp->address, sizeof(resp->address));
#else
        base58_encode_check(buf, 21, secp256k1_info.hasher_base58, resp->address, sizeof(resp->address));
#endif
    }
    else
    {
#if 0
        ecdsa_get_address(node->public_key, coin->address_type, coin->curve->hasher_pubkey,
                          coin->curve->hasher_base58,resp->address,
                          sizeof(resp->address));
#else
        ecdsa_get_address(node->public_key, coin->address_type, secp256k1_info.hasher_pubkey,
                          secp256k1_info.hasher_base58, resp->address,
                          sizeof(resp->address));
#endif
    }

    if(msg->has_show_display && msg->show_display)
    {
        char desc[MEDIUM_STR_BUF] = "";

        if(msg->has_multisig)
        {
            const uint32_t m = msg->multisig.m;
            const uint32_t n = msg->multisig.pubkeys_count;

            /* snprintf: 22 + 10 (%lu) + 10 (%lu) + 1 (NULL) = 43 */
            snprintf(desc, MEDIUM_STR_BUF, "(Multi-Signature %lu of %lu)", (unsigned long)m,
                     (unsigned long)n);
        }

        if(!confirm_address(desc, resp->address))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, "Show address cancelled");
            go_home();
            return;
        }
    }

    msg_write(MessageType_MessageType_Address, resp);
    go_home();
}

void fsm_msgSignMessage(SignMessage *msg)
{
    RESP_INIT(MessageSignature);

    if (!storage_isInitialized())
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
        return;
    }

    if(!confirm(ButtonRequestType_ButtonRequest_SignMessage, "Sign Message", "%s",
                (char *)msg->message.bytes))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Sign message cancelled");
        go_home();
        return;
    }

    if(!pin_protect_cached())
    {
        go_home();
        return;
    }

    const CoinType *coin = fsm_getCoin(msg->coin_name);

    if(!coin) { return; }

    HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count);

    if(!node) { return; }

    if(cryptoMessageSign(coin, node, InputScriptType_SPENDADDRESS, msg->message.bytes, msg->message.size, resp->signature.bytes) == 0 &&
       coin->has_address_type)
    {
        resp->has_address = true;
        hdnode_fill_public_key(node);
        hdnode_get_address(node, coin->address_type, resp->address, sizeof(resp->address));
        resp->has_signature = true;
        resp->signature.size = 65;
        msg_write(MessageType_MessageType_MessageSignature, resp);
    }
    else
    {
        fsm_sendFailure(FailureType_Failure_Other, "Error signing message");
    }
    go_home();
}

void fsm_msgVerifyMessage(VerifyMessage *msg)
{
    if(!msg->has_address)
    {
        fsm_sendFailure(FailureType_Failure_Other, "No address provided");
        return;
    }

    if(!msg->has_message)
    {
        fsm_sendFailure(FailureType_Failure_Other, "No message provided");
        return;
    }
    const CoinType *coin = fsm_getCoin(msg->coin_name);
    if (!coin) return;
    layout_simple_message("Verifying Message...");
    uint8_t addr_raw[21];

#if 0
    if(!ecdsa_address_decode(msg->address, coin->address_type, coin->curve->hasher_base58, addr_raw))
#else
    if(!ecdsa_address_decode(msg->address, coin->address_type, secp256k1_info.hasher_base58, addr_raw))
#endif
    {
        fsm_sendFailure(FailureType_Failure_InvalidSignature, "Invalid address");
    }
    if(msg->signature.size == 65 &&
            cryptoMessageVerify(coin, msg->message.bytes, msg->message.size, msg->address,
                                msg->signature.bytes) == 0)
    {
        if(review(ButtonRequestType_ButtonRequest_Other, "Message Verified", "%s",
                  (char *)msg->message.bytes))
        {
            fsm_sendSuccess("Message verified");
        }
    }
    else
    {
        fsm_sendFailure(FailureType_Failure_InvalidSignature, "Invalid signature");
    }

    go_home();
}

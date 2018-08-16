void fsm_msgCipherKeyValue(CipherKeyValue *msg)
{

    if (!storage_isInitialized())
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
        return;
    }

    if(!msg->has_key)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No key provided");
        return;
    }

    if(!msg->has_value)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError, "No value provided");
        return;
    }

    if(msg->value.size % 16)
    {
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        "Value length must be a multiple of 16");
        return;
    }

    if(!pin_protect_cached())
    {
        go_home();
        return;
    }

    const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count);

    if(!node) { return; }

    bool encrypt = msg->has_encrypt && msg->encrypt;
    bool ask_on_encrypt = msg->has_ask_on_encrypt && msg->ask_on_encrypt;
    bool ask_on_decrypt = msg->has_ask_on_decrypt && msg->ask_on_decrypt;

    if((encrypt && ask_on_encrypt) || (!encrypt && ask_on_decrypt))
    {
        if(!confirm_cipher(encrypt, msg->key))
        {
            fsm_sendFailure(FailureType_Failure_ActionCancelled,
                            "CipherKeyValue cancelled");
            go_home();
            return;
        }
    }

    uint8_t data[256 + 4];
    strlcpy((char *)data, msg->key, sizeof(data));
    strlcat((char *)data, ask_on_encrypt ? "E1" : "E0", sizeof(data));
    strlcat((char *)data, ask_on_decrypt ? "D1" : "D0", sizeof(data));

    hmac_sha512(node->private_key, 32, data, strlen((char *)data), data);

    RESP_INIT(CipheredKeyValue);

    if(encrypt)
    {
        aes_encrypt_ctx ctx;
        aes_encrypt_key256(data, &ctx);
        aes_cbc_encrypt(msg->value.bytes, resp->value.bytes, msg->value.size,
                        ((msg->iv.size == 16) ? (msg->iv.bytes) : (data + 32)), &ctx);
    }
    else
    {
        aes_decrypt_ctx ctx;
        aes_decrypt_key256(data, &ctx);
        aes_cbc_decrypt(msg->value.bytes, resp->value.bytes, msg->value.size,
                        ((msg->iv.size == 16) ? (msg->iv.bytes) : (data + 32)), &ctx);
    }

    resp->has_value = true;
    resp->value.size = msg->value.size;
    msg_write(MessageType_MessageType_CipheredKeyValue, resp);
    go_home();
}

void fsm_msgSignIdentity(SignIdentity *msg)
{
    RESP_INIT(SignedIdentity);

    if (!storage_isInitialized())
    {
        fsm_sendFailure(FailureType_Failure_NotInitialized, "Device not initialized");
        return;
    }

    if (!confirm_sign_identity(&(msg->identity), msg->has_challenge_visual ? msg->challenge_visual : 0))
    {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, "Sign identity cancelled");
        go_home();
        return;
    }

    if (!pin_protect_cached())
    {
        go_home();
        return;
    }

    uint8_t hash[32];
    if (!msg->has_identity || cryptoIdentityFingerprint(&(msg->identity), hash) == 0)
    {
        fsm_sendFailure(FailureType_Failure_Other, "Invalid identity");
        go_home();
        return;
    }

    uint32_t address_n[5];
    address_n[0] = 0x80000000 | 13;
    address_n[1] = 0x80000000 | hash[ 0] | (hash[ 1] << 8) | (hash[ 2] << 16) | ((uint32_t)hash[ 3] << 24);
    address_n[2] = 0x80000000 | hash[ 4] | (hash[ 5] << 8) | (hash[ 6] << 16) | ((uint32_t)hash[ 7] << 24);
    address_n[3] = 0x80000000 | hash[ 8] | (hash[ 9] << 8) | (hash[10] << 16) | ((uint32_t)hash[11] << 24);
    address_n[4] = 0x80000000 | hash[12] | (hash[13] << 8) | (hash[14] << 16) | ((uint32_t)hash[15] << 24);

    const char *curve = SECP256K1_NAME;
    if (msg->has_ecdsa_curve_name) {
        curve = msg->ecdsa_curve_name;
    }
    HDNode *node = fsm_getDerivedNode(curve, address_n, 5);
    if (!node) { return; }

    bool sign_ssh = msg->identity.has_proto && (strcmp(msg->identity.proto, "ssh") == 0);
    bool sign_gpg = msg->identity.has_proto && (strcmp(msg->identity.proto, "gpg") == 0);

    int result = 0;
    layout_simple_message("Signing Identity...");

    if (sign_ssh) {   // SSH does not sign visual challenge
        result = sshMessageSign(node, msg->challenge_hidden.bytes, msg->challenge_hidden.size, resp->signature.bytes);
    } else if (sign_gpg) { // GPG should sign a message digest
        result = gpgMessageSign(node, msg->challenge_hidden.bytes, msg->challenge_hidden.size, resp->signature.bytes);
    } else {
        uint8_t digest[64];
        sha256_Raw(msg->challenge_hidden.bytes, msg->challenge_hidden.size, digest);
        sha256_Raw((const uint8_t *)msg->challenge_visual, strlen(msg->challenge_visual), digest + 32);
        result = cryptoMessageSign(coinByName("Bitcoin"), node, InputScriptType_SPENDADDRESS, digest, 64, resp->signature.bytes);
    }

    if (result == 0) {
        hdnode_fill_public_key(node);
        if (strcmp(curve, SECP256K1_NAME) != 0)
        {
            resp->has_address = false;
        }
        else
        {
            resp->has_address = true;
            hdnode_fill_public_key(node);
            hdnode_get_address(node, 0x00, resp->address, sizeof(resp->address)); // hardcoded Bitcoin address type
        }
        resp->has_public_key = true;
        resp->public_key.size = 33;
        memcpy(resp->public_key.bytes, node->public_key, 33);
        if (node->public_key[0] == 1) {
            /* ed25519 public key */
            resp->public_key.bytes[0] = 0;
        }
        resp->has_signature = true;
        resp->signature.size = 65;
        msg_write(MessageType_MessageType_SignedIdentity, resp);
    }
    else
    {
        fsm_sendFailure(FailureType_Failure_Other, "Error signing identity");
    }

    go_home();
}

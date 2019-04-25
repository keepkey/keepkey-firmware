#if DEBUG_LINK
void fsm_msgDebugLinkGetState(DebugLinkGetState *msg)
{
    (void)msg;
    RESP_INIT(DebugLinkState);

    if(storage_hasPin())
    {
        resp->has_pin = true;
        strlcpy(resp->pin, storage_getPin(), sizeof(resp->pin));
    }

    resp->has_matrix = true;
    strlcpy(resp->matrix, get_pin_matrix(), sizeof(resp->matrix));

    resp->has_reset_entropy = true;
    resp->reset_entropy.size = reset_get_int_entropy(resp->reset_entropy.bytes);

    resp->has_reset_word = true;
    strlcpy(resp->reset_word, reset_get_word(), sizeof(resp->reset_word));

    resp->has_recovery_fake_word = true;
    strlcpy(resp->recovery_fake_word, recovery_get_fake_word(),
            sizeof(resp->recovery_fake_word));

    resp->has_recovery_word_pos = true;
    resp->recovery_word_pos = recovery_get_word_pos();

    if(storage_hasMnemonic())
    {
        resp->has_mnemonic = true;
        strlcpy(resp->mnemonic, storage_getMnemonic(), sizeof(resp->mnemonic));
    }

    if(storage_hasNode())
    {
        resp->has_node = true;
        storage_dumpNode(&resp->node, storage_getNode());
    }

    resp->has_passphrase_protection = true;
    resp->passphrase_protection = storage_getPassphraseProtected();

    resp->has_recovery_cipher = true;
    strlcpy(resp->recovery_cipher, recovery_get_cipher(),
            sizeof(resp->recovery_cipher));

    resp->has_recovery_auto_completed_word = true;
    strlcpy(resp->recovery_auto_completed_word, recovery_get_auto_completed_word(),
            sizeof(resp->recovery_auto_completed_word));

    resp->has_firmware_hash = true;
    resp->firmware_hash.size = memory_firmware_hash(resp->firmware_hash.bytes);

    resp->has_storage_hash = true;
    resp->storage_hash.size = memory_storage_hash(resp->storage_hash.bytes,
                                                  storage_getLocation());

    msg_debug_write(MessageType_MessageType_DebugLinkState, resp);
}

void fsm_msgDebugLinkStop(DebugLinkStop *msg)
{
    (void)msg;
}

void fsm_msgDebugLinkFlashDump(DebugLinkFlashDump *msg)
{
#ifndef EMULATOR
    if (!msg->has_length || msg->length > sizeof(((DebugLinkFlashDumpResponse *)0)->data.bytes)) {
#endif
        fsm_sendFailure(FailureType_Failure_Other, "Invalid FlashDump parameters");
        layoutHome();
        return;
#ifndef EMULATOR
    }

    RESP_INIT(DebugLinkFlashDumpResponse);

    memcpy(resp->data.bytes, (void*)msg->address, msg->length);

    resp->has_data = true;
    resp->data.size = msg->length;
    msg_write(MessageType_MessageType_DebugLinkFlashDumpResponse, resp);
#endif
}

#endif

#if DEBUG_LINK
void fsm_msgDebugLinkGetState(DebugLinkGetState *msg)
{
    (void)msg;
    RESP_INIT(DebugLinkState);

    if(storage_has_pin())
    {
        resp->has_pin = true;
        strlcpy(resp->pin, storage_get_pin(), sizeof(resp->pin));
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

    if(storage_has_mnemonic())
    {
        resp->has_mnemonic = true;
        strlcpy(resp->mnemonic, storage_get_mnemonic(), sizeof(resp->mnemonic));
    }

    if(storage_has_node())
    {
        resp->has_node = true;
        storage_dumpNode(&resp->node, storage_get_node());
    }

    resp->has_passphrase_protection = true;
    resp->passphrase_protection = storage_get_passphrase_protected();

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
                              get_storage_location());

    msg_debug_write(MessageType_MessageType_DebugLinkState, resp);
}

void fsm_msgDebugLinkStop(DebugLinkStop *msg)
{
    (void)msg;
}
#endif

void fsm_msgDebugLinkFlashDump(DebugLinkFlashDump *msg)
{
#ifndef EMULATOR
    if (!msg->has_length || msg->length > sizeof(((DebugLinkFlashDumpResponse *)0)->data.bytes)) {
#endif
        fsm_sendFailure(FailureType_Failure_Other, "Invalid FlashDump parameters");
        go_home();
        return;
#ifndef EMULATOR
    }

    RESP_INIT(DebugLinkFlashDumpResponse);

#  if DEBUG_LINK
    memcpy(resp->data.bytes, (void*)msg->address, msg->length);
#  else
    if (variant_mfr_flashDump)
        variant_mfr_flashDump(resp->data.bytes, (void*)msg->address, msg->length);
#  endif

    resp->has_data = true;
    resp->data.size = msg->length;
    msg_write(MessageType_MessageType_DebugLinkFlashDumpResponse, resp);
#endif
}

void fsm_msgSoftReset(SoftReset *msg) {
    (void)msg;
    if (variant_mfr_softReset)
        variant_mfr_softReset();
    else {
        fsm_sendFailure(FailureType_Failure_Other, "SoftReset: unsupported outside of MFR firmware");
        go_home();
    }
}

void fsm_msgFlashWrite(FlashWrite *msg) {
#ifndef EMULATOR
    if (!variant_mfr_flashWrite || !variant_mfr_flashHash ||
        !variant_mfr_sectorFromAddress || !variant_mfr_sectorLength ||
        !variant_mfr_sectorStart) {
#endif
        fsm_sendFailure(FailureType_Failure_Other, "FlashWrite: this isn't MFR firmware");
        go_home();
        return;
#ifndef EMULATOR
    }

    if (!msg->has_address || !msg->has_data || msg->data.size > 1024) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashWrite: invalid parameters");
        go_home();
        return;
    }

    uint8_t sector = variant_mfr_sectorFromAddress((uint8_t*)msg->address);
    if (variant_mfr_sectorLength(sector) < (uint8_t*)msg->address -
                                  (uint8_t*)variant_mfr_sectorStart(sector) +
                                  msg->data.size) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashWrite: write must not span more than one sector");
        go_home();
        return;
    }

    _Static_assert(FLASH_BOOTSTRAP_SECTOR_FIRST == FLASH_BOOTSTRAP_SECTOR_LAST,
                   "Bootstrap isn't one sector?");
    if (FLASH_BOOTSTRAP_SECTOR_FIRST == sector ||
        (FLASH_VARIANT_SECTOR_FIRST <= sector &&
         sector <= FLASH_VARIANT_SECTOR_LAST) ||
        (FLASH_BOOT_SECTOR_FIRST <= sector &&
         sector <= FLASH_BOOT_SECTOR_LAST)) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashWrite: cannot write to read-only sector");
        go_home();
        return;
    }

    if (!variant_mfr_flashWrite((uint8_t*)msg->address, msg->data.bytes, msg->data.size,
                                 msg->has_erase ? msg->erase : false)) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashWrite: write failed");
        go_home();
        return;
    }

    if (memcmp((void*)msg->address, (void*)msg->data.bytes, msg->data.size) != 0) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashWrite: write / read-back mismatch");
        go_home();
        return;
    }

    RESP_INIT(FlashHashResponse);

    if (!variant_mfr_flashHash((uint8_t*)msg->address, msg->data.size, 0, 0,
                                resp->data.bytes, sizeof(resp->data.bytes))) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashWrite: FlashHash failed");
        go_home();
        return;
    }

    resp->has_data = true;
    resp->data.size = sizeof(resp->data.bytes);
    msg_write(MessageType_MessageType_FlashHashResponse, resp);
#endif
}

void fsm_msgFlashHash(FlashHash *msg) {
#ifndef EMULATOR
    if (!variant_mfr_flashHash) {
#endif
        fsm_sendFailure(FailureType_Failure_Other, "FlashHash: this isn't MFR firmware");
        go_home();
        return;
#ifndef EMULATOR
    }

    if (!msg->has_address || !msg->has_length || !msg->has_challenge) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashHash: invalid parameters");
        go_home();
        return;
    }

    RESP_INIT(FlashHashResponse);

    if (!variant_mfr_flashHash((uint8_t*)msg->address, msg->length,
                                msg->challenge.bytes, msg->challenge.size,
                                resp->data.bytes, sizeof(resp->data.bytes))) {
        fsm_sendFailure(FailureType_Failure_Other, "FlashHash: failed");
        go_home();
        return;
    }

    resp->has_data = true;
    resp->data.size = sizeof(resp->data.bytes);
    msg_write(MessageType_MessageType_FlashHashResponse, resp);
#endif
}

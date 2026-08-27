#if DEBUG_LINK
void fsm_msgDebugLinkGetState(DebugLinkGetState* msg) {
  (void)msg;
  RESP_INIT(DebugLinkState);

  if (storage_hasPin()) {
    resp->has_pin = true;
    strlcpy(resp->pin, storage_getPin(), sizeof(resp->pin));
  }

  resp->has_matrix = true;
  strlcpy(resp->matrix, get_pin_matrix(), sizeof(resp->matrix));

  resp->has_reset_entropy = true;
  resp->reset_entropy.size = reset_get_int_entropy(resp->reset_entropy.bytes);

  resp->has_reset_word = true;
  strlcpy(resp->reset_word, reset_get_word(), sizeof(resp->reset_word));

  if (storage_hasMnemonic()) {
    resp->has_mnemonic = true;
    strlcpy(resp->mnemonic, storage_getMnemonic(), sizeof(resp->mnemonic));
  }

  if (storage_hasNode()) {
    resp->has_node = true;
    storage_dumpNode(&resp->node, storage_getNode());
  }

  resp->has_passphrase_protection = true;
  resp->passphrase_protection = storage_getPassphraseProtected();

  resp->has_recovery_cipher = true;
  strlcpy(resp->recovery_cipher, recovery_get_cipher(),
          sizeof(resp->recovery_cipher));

  resp->has_recovery_auto_completed_word = true;
  strlcpy(resp->recovery_auto_completed_word,
          recovery_get_auto_completed_word(),
          sizeof(resp->recovery_auto_completed_word));

  resp->has_firmware_hash = true;
  resp->firmware_hash.size = memory_firmware_hash(resp->firmware_hash.bytes);

  resp->has_storage_hash = true;
  resp->storage_hash.size =
      memory_storage_hash(resp->storage_hash.bytes, storage_getLocation());

  /* Just refresh the display — don't force animations.
   * The confirm() loop already ran animate() before sending ButtonRequest,
   * so the canvas has the correct content. Calling force_animation_start()
   * + animate() here would either: (a) do nothing if the queue is empty,
   * or (b) re-run an animation that overwrites static content.
   * display_refresh() ensures the framebuffer is synced for reading. */
  display_refresh();

  /* Pack 256x64 grayscale canvas into 1bpp layout for screenshot capture.
   * Each byte in layout holds 8 vertical pixels (LSB = top).
   * Total: 256 columns x (64/8) rows = 2048 bytes. */
  {
    const Canvas* c = display_canvas();
    if (c && c->buffer) {
      resp->has_layout = true;
      resp->layout.size = 2048;
      memset(resp->layout.bytes, 0, 2048);
      for (int x = 0; x < 256; x++) {
        for (int y = 0; y < 64; y++) {
          if (c->buffer[y * 256 + x] > 0) {
            resp->layout.bytes[x + (y / 8) * 256] |= (1 << (y % 8));
          }
        }
      }
    }
  }

  msg_debug_write(MessageType_MessageType_DebugLinkState, resp);
}

void fsm_msgDebugLinkStop(DebugLinkStop* msg) { (void)msg; }

void fsm_msgDebugLinkFlashDump(DebugLinkFlashDump* msg) {
#ifndef EMULATOR
  if (!msg->has_length ||
      msg->length > sizeof(((DebugLinkFlashDumpResponse*)0)->data.bytes)) {
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

void fsm_msgGetBip85Mnemonic(const GetBip85Mnemonic *msg) {
  CHECK_INITIALIZED

  /* Validate word count */
  if (msg->word_count != 12 && msg->word_count != 18 && msg->word_count != 24) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "word_count must be 12, 18, or 24");
    layoutHome();
    return;
  }

  CHECK_PIN

  /* User confirmation on device display */
  char desc[80];
  snprintf(desc, sizeof(desc),
           "Derive %lu-word child seed at index %lu?",
           (unsigned long)msg->word_count, (unsigned long)msg->index);

  if (!confirm(ButtonRequestType_ButtonRequest_Other,
               "BIP-85 Derive Seed", "%s", desc)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "BIP-85 derivation cancelled");
    layoutHome();
    return;
  }

  layout_simple_message("Deriving child seed...");

  /* Derive the mnemonic */
  static CONFIDENTIAL char mnemonic_buf[241];
  if (!bip85_derive_mnemonic(msg->word_count, msg->index,
                             mnemonic_buf, sizeof(mnemonic_buf))) {
    memzero(mnemonic_buf, sizeof(mnemonic_buf));
    fsm_sendFailure(FailureType_Failure_Other,
                    "BIP-85 derivation failed");
    layoutHome();
    return;
  }

  /* Send response */
  RESP_INIT(Bip85Mnemonic);
  strlcpy(resp->mnemonic, mnemonic_buf, sizeof(resp->mnemonic));
  memzero(mnemonic_buf, sizeof(mnemonic_buf));

  msg_write(MessageType_MessageType_Bip85Mnemonic, resp);
  layoutHome();
}

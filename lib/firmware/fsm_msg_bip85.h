void fsm_msgGetBip85Mnemonic(const GetBip85Mnemonic *msg) {
  CHECK_INITIALIZED

  /* Validate required fields are present */
  if (!msg->has_word_count || !msg->has_index) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "word_count and index are required");
    layoutHome();
    return;
  }

  /* Validate word count */
  if (msg->word_count != 12 && msg->word_count != 18 && msg->word_count != 24) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "word_count must be 12, 18, or 24");
    layoutHome();
    return;
  }

  /* Reject index >= 0x80000000 (hardened-bit collision) */
  if (msg->index & 0x80000000) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "index must be less than 2147483648");
    layoutHome();
    return;
  }

  CHECK_PIN

  /* User confirmation — make clear a secret is being exported */
  char desc[80];
  snprintf(desc, sizeof(desc),
           "Export %lu-word child seed at index %lu to host?",
           (unsigned long)msg->word_count, (unsigned long)msg->index);

  if (!confirm(ButtonRequestType_ButtonRequest_Other,
               "BIP-85 Export Seed", "%s", desc)) {
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

  /* Second confirmation before sending secret to host */
  if (!confirm(ButtonRequestType_ButtonRequest_Other,
               "Send to Computer?",
               "The child seed will be sent to the connected computer. Continue?")) {
    memzero(mnemonic_buf, sizeof(mnemonic_buf));
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "BIP-85 export cancelled");
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

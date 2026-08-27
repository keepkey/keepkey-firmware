void fsm_msgGetBip85Mnemonic(const GetBip85Mnemonic *msg) {
  CHECK_INITIALIZED

  /* Validate word count (required field, always present in nanopb) */
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

  /* User confirmation */
  char desc[80];
  snprintf(desc, sizeof(desc), "Derive %lu-word child seed at index %lu?",
           (unsigned long)msg->word_count, (unsigned long)msg->index);

  if (!confirm(ButtonRequestType_ButtonRequest_Other, "BIP-85 Derive Seed",
               "%s", desc)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "BIP-85 derivation cancelled");
    layoutHome();
    return;
  }

  layout_simple_message("Deriving child seed...");

  /* Derive the mnemonic */
  static CONFIDENTIAL char mnemonic_buf[241];
  if (!bip85_derive_mnemonic(msg->word_count, msg->index, mnemonic_buf,
                             sizeof(mnemonic_buf))) {
    memzero(mnemonic_buf, sizeof(mnemonic_buf));
    fsm_sendFailure(FailureType_Failure_Other, "BIP-85 derivation failed");
    layoutHome();
    return;
  }

  /*
   * Display mnemonic on device screen only — never send over USB.
   * Uses the same paginated display as the backup flow in reset.c.
   */
  uint32_t word_count = 0, page_count = 0;

  /* Display scratch shared with the backup flow — see reset.h. Zero the whole
   * set at entry per the sharing contract (a prior user may have aborted). */
  memzero(mnemonic_scratch_tokened, sizeof(mnemonic_scratch_tokened));
  memzero(mnemonic_scratch_formatted, sizeof(mnemonic_scratch_formatted));
  memzero(mnemonic_scratch_display, sizeof(mnemonic_scratch_display));
  memzero(mnemonic_scratch_word, sizeof(mnemonic_scratch_word));

  strlcpy(mnemonic_scratch_tokened, mnemonic_buf, TOKENED_MNEMONIC_BUF);
  memzero(mnemonic_buf, sizeof(mnemonic_buf));

  const char *tok = strtok(mnemonic_scratch_tokened, " ");

  while (tok) {
    snprintf(mnemonic_scratch_word, MAX_WORD_LEN + ADDITIONAL_WORD_PAD,
             (word_count & 1) ? "%lu.%s\n" : "%lu.%s",
             (unsigned long)(word_count + 1), tok);

    /* Check that we have enough room on display to show word */
    snprintf(mnemonic_scratch_display, FORMATTED_MNEMONIC_BUF, "%s   %s",
             mnemonic_scratch_formatted[page_count], mnemonic_scratch_word);

    if (calc_str_line(get_body_font(), mnemonic_scratch_display, BODY_WIDTH) >
        3) {
      page_count++;

      if (MAX_PAGES <= page_count) {
        memzero(mnemonic_scratch_tokened, sizeof(mnemonic_scratch_tokened));
        memzero(mnemonic_scratch_formatted, sizeof(mnemonic_scratch_formatted));
        memzero(mnemonic_scratch_display, sizeof(mnemonic_scratch_display));
        memzero(mnemonic_scratch_word, sizeof(mnemonic_scratch_word));
        fsm_sendFailure(FailureType_Failure_Other,
                        "Too many pages of mnemonic words");
        layoutHome();
        return;
      }

      snprintf(mnemonic_scratch_display, FORMATTED_MNEMONIC_BUF, "%s   %s",
               mnemonic_scratch_formatted[page_count], mnemonic_scratch_word);
    }

    strlcpy(mnemonic_scratch_formatted[page_count], mnemonic_scratch_display,
            FORMATTED_MNEMONIC_BUF);

    tok = strtok(NULL, " ");
    word_count++;
  }

  /* Switch from 0-indexing to 1-indexing */
  page_count++;

  display_constant_power(true);

  /* Show each page of the mnemonic on screen */
  for (uint32_t current_page = 0; current_page < page_count; current_page++) {
    char title[MEDIUM_STR_BUF];

    if (page_count > 1) {
      snprintf(title, MEDIUM_STR_BUF, "BIP-85 Seed %" PRIu32 "/%" PRIu32,
               current_page + 1, page_count);
    } else {
      snprintf(title, MEDIUM_STR_BUF, "BIP-85 Seed");
    }

    if (!confirm_constant_power(ButtonRequestType_ButtonRequest_ConfirmWord,
                                title, "%s",
                                mnemonic_scratch_formatted[current_page])) {
      memzero(mnemonic_scratch_tokened, sizeof(mnemonic_scratch_tokened));
      memzero(mnemonic_scratch_formatted, sizeof(mnemonic_scratch_formatted));
      memzero(mnemonic_scratch_display, sizeof(mnemonic_scratch_display));
      memzero(mnemonic_scratch_word, sizeof(mnemonic_scratch_word));
      display_constant_power(false);
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "BIP-85 display cancelled");
      layoutHome();
      return;
    }
  }

  display_constant_power(false);

  /* Wipe all sensitive buffers */
  memzero(mnemonic_scratch_tokened, sizeof(mnemonic_scratch_tokened));
  memzero(mnemonic_scratch_formatted, sizeof(mnemonic_scratch_formatted));
  memzero(mnemonic_scratch_display, sizeof(mnemonic_scratch_display));
  memzero(mnemonic_scratch_word, sizeof(mnemonic_scratch_word));

  /* Send success — mnemonic is NOT sent over the wire */
  fsm_sendSuccess("BIP-85 seed displayed on device");
  layoutHome();
}

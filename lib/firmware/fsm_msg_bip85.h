static void bip85_finish_private_display(void) {
  /* Clear the last mnemonic page before diagnostics become available again. */
  layout_clear();
  layoutHome();
#if DEBUG_LINK
  confirm_debug_clear();
#endif
  bip85_set_private_display(false);
}

void fsm_msgGetBip85Mnemonic(const GetBip85Mnemonic *msg) {
  CHECK_INITIALIZED

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
  bip85_set_private_display(true);

  static CONFIDENTIAL char mnemonic_buf[241];
  if (!bip85_derive_mnemonic(msg->word_count, msg->index, mnemonic_buf,
                             sizeof(mnemonic_buf))) {
    memzero(mnemonic_buf, sizeof(mnemonic_buf));
    fsm_sendFailure(FailureType_Failure_Other, "BIP-85 derivation failed");
    bip85_finish_private_display();
    return;
  }

  /* Display on device only; never send over USB. */
  uint32_t word_count = 0, page_count = 0;

  /* Display scratch shared with the backup flow — see reset.h. Zero the whole
   * set at entry per the sharing contract (a prior user may have aborted). */
  mnemonic_scratch_wipe();

  strlcpy(mnemonic_scratch_tokened, mnemonic_buf, TOKENED_MNEMONIC_BUF);
  memzero(mnemonic_buf, sizeof(mnemonic_buf));

  const char *tok = strtok(mnemonic_scratch_tokened, " ");

  while (tok) {
    snprintf(mnemonic_scratch_word, MAX_WORD_LEN + ADDITIONAL_WORD_PAD,
             (word_count & 1) ? "%lu.%s\n" : "%lu.%s",
             (unsigned long)(word_count + 1), tok);

    snprintf(mnemonic_scratch_display, FORMATTED_MNEMONIC_BUF, "%s   %s",
             mnemonic_scratch_formatted[page_count], mnemonic_scratch_word);

    if (calc_str_line(get_body_font(), mnemonic_scratch_display, BODY_WIDTH) >
        3) {
      page_count++;

      if (MAX_PAGES <= page_count) {
        mnemonic_scratch_wipe();
        fsm_sendFailure(FailureType_Failure_Other,
                        "Too many pages of mnemonic words");
        bip85_finish_private_display();
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

  page_count++;

  display_constant_power(true);

  for (uint32_t current_page = 0; current_page < page_count; current_page++) {
    char title[MEDIUM_STR_BUF];

    if (page_count > 1) {
      snprintf(title, MEDIUM_STR_BUF, "BIP-85 Seed %" PRIu32 "/%" PRIu32,
               current_page + 1, page_count);
    } else {
      snprintf(title, MEDIUM_STR_BUF, "BIP-85 Seed");
    }

    /* Paged: the unpaged renderer silently drops words that do not fit the
     * 124 px half-canvas, and a dropped word is an unrecoverable wallet. */
    if (!confirm_constant_power_paged(
            ButtonRequestType_ButtonRequest_ConfirmWord, title,
            mnemonic_scratch_formatted[current_page])) {
      mnemonic_scratch_wipe();
      display_constant_power(false);
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      "BIP-85 display cancelled");
      bip85_finish_private_display();
      return;
    }
  }

  display_constant_power(false);

  /* Wipe all sensitive buffers */
  mnemonic_scratch_wipe();

  /* Send success — mnemonic is NOT sent over the wire */
  fsm_sendSuccess("BIP-85 seed displayed on device");
  bip85_finish_private_display();
}

/* Compile the real implementation into firmware-unit to inspect live scratch;
 * production has neither a secret getter nor test mutation hooks. */
#include "keepkey/board/layout.h"
#include "keepkey/firmware/app_layout.h"

static unsigned cipher_draws;
static void observed_layout_cipher(const char* current_word, const char* cipher,
                                   const char* previous, bool animate) {
  ++cipher_draws;
  layout_cipher(current_word, cipher, previous, animate);
}

#define layout_cipher observed_layout_cipher
#include "../../lib/firmware/recovery_cipher.c"
#undef layout_cipher

void recovery_review_reset_cipher_draws(void) { cipher_draws = 0; }
unsigned recovery_review_cipher_draws(void) { return cipher_draws; }

bool recovery_review_scratch_empty(void) {
  /* prev_info is function-local in render_current_cipher() and wiped before it
   * returns, so last_completed_word is the only file-scope previous-word copy.
   */
  for (size_t i = 0; i < sizeof(last_completed_word); ++i)
    if (last_completed_word[i]) return false;
  return true;
}

void recovery_review_seed_scratch(void) {
  strcpy(last_completed_word, "abandon");
}

/* Delete resync with a controlled mnemonic (already edited) and the coded
 * characters the user really typed. The cipher is set to the identity, so a
 * resync that recomputed coded characters from it would visibly differ. */
bool recovery_review_delete_resync(const char* mnemonic_after_delete,
                                   const char* typed, bool unknown,
                                   char coded_out[12], char decoded_out[12]) {
  strlcpy(mnemonic, mnemonic_after_delete, sizeof(mnemonic));
  strlcpy(coded_word, typed, sizeof(coded_word));
  strlcpy(cipher, english_alphabet, sizeof(cipher));
  coded_word_unknown = unknown;
  resync_current_word_after_delete();
  memcpy(coded_out, coded_word, sizeof(coded_word));
  memcpy(decoded_out, decoded_word, sizeof(decoded_word));
  const bool result = coded_word_unknown;
  recovery_cipher_reset();
  return result;
}

/* Previous-word resync after a delete removed the separator of the word the
 * indicator named. */
void recovery_review_previous_after_delete(const char* mnemonic_after_delete,
                                           char previous_out[12]) {
  strlcpy(mnemonic, mnemonic_after_delete, sizeof(mnemonic));
  strlcpy(last_completed_word, "stale", sizeof(last_completed_word));
  resync_previous_word_after_delete();
  memcpy(previous_out, last_completed_word, sizeof(last_completed_word));
  recovery_cipher_reset();
}

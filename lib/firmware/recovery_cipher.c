/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2015 KeepKey LLC
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "keepkey/firmware/recovery_cipher.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/pin_sm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng.h"
#include "hwcrypto/crypto/bip39.h"
#include "hwcrypto/crypto/bip39_english.h"
#include "hwcrypto/crypto/memzero.h"

#include <string.h>
#include <stdio.h>

#if DEBUG_LINK
#include <assert.h>
#endif

#define MAX_UNCYPHERED_WORDS (3)

static uint32_t word_count = 0;
static uint32_t words_entered = 0;
static bool recovery_started = false;
static bool enforce_wordlist = true;
static bool dry_run = true;
static bool awaiting_character;
static CONFIDENTIAL char mnemonic[MNEMONIC_BUF];
static char english_alphabet[ENGLISH_ALPHABET_BUF] =
    "abcdefghijklmnopqrstuvwxyz";
static CONFIDENTIAL char cipher[ENGLISH_ALPHABET_BUF];

#if DEBUG_LINK
static char auto_completed_word[CURRENT_WORD_BUF];
#endif

static uint32_t get_current_word_pos(void);
static void get_current_word(char *current_word);

void recovery_cipher_abort(void) {
  if (!dry_run) {
    storage_reset();
  }

  recovery_started = false;
  awaiting_character = false;
  enforce_wordlist = true;
  dry_run = true;
  words_entered = 0;
  word_count = 0;
  memzero(mnemonic, sizeof(mnemonic));
  memzero(cipher, sizeof(cipher));
}

/// Formats the passed word to show position in mnemonic as well as characters
/// left.
///
/// \param current_word[in]    The string to format.
/// \param auto_completed[in]  Whether to format as an auto completed word.
static void format_current_word(uint32_t word_pos, const char *current_word,
                                bool auto_completed,
                                char (*formatted_word)[CURRENT_WORD_BUF + 10]) {
  uint32_t word_num = word_pos + 1;

  snprintf(*formatted_word, sizeof(*formatted_word), "%" PRIu32 ".%s", word_num,
           current_word);

  /* Pad with dashes */
  size_t pos_len = strlen(current_word);
  if (pos_len < 4) {
    for (size_t i = 0; i < 4 - pos_len; i++) {
      strlcat(*formatted_word, "-", sizeof(*formatted_word));
    }
  }

  /* Mark as auto completed */
  if (auto_completed) {
    (*formatted_word)[strlen(*formatted_word) + 1] = '\0';
    (*formatted_word)[strlen(*formatted_word)] = '~';
  }
}

/*
 * get_current_word_pos() - Returns the current word position in the mnemonic
 *
 * INPUT
 *     none
 * OUTPUT
 *     position in mnemonic
 */
static uint32_t get_current_word_pos(void) {
  char *pos_num = strchr(mnemonic, ' ');
  uint32_t word_pos = 0;

  while (pos_num != NULL) {
    word_pos++;
    pos_num = strchr(++pos_num, ' ');
  }

  return word_pos;
}

/// \returns the current word being entered by parsing the mnemonic thus far
/// \param current_word[out]  Array to populate with current word.
static void get_current_word(char *current_word) {
  char *pos = strrchr(mnemonic, ' ');

  if (pos) {
    pos++;
    strlcpy(current_word, pos, CURRENT_WORD_BUF);
  } else {
    strlcpy(current_word, mnemonic, CURRENT_WORD_BUF);
  }
}

_Static_assert(BIP39_WORDLIST_PADDED,
               "bip39 wordlist must be padded to 9 characters");

bool exact_str_match(const char *str1, const char *str2, uint32_t len) {
  volatile uint32_t match = 0;

  // Access through volatile ptrs to prevent compiler optimizations that
  // might leak timing information.
  const char volatile *volatile str1_v = str1;
  const char volatile *volatile str2_v = str2;

  for (uint32_t i = 0;
       i < len && i < CURRENT_WORD_BUF && i <= BIP39_MAX_WORD_LEN; i++) {
    if (str1_v[i] == str2_v[i]) {
      match++;
    } else {
      match--;
    }
  }

  return match == len;
}

#define BIP39_MAX_WORD_LEN 8

bool attempt_auto_complete(char *partial_word) {
  // Do lookup through volatile pointers to prevent the compiler from
  // optimizing this loop into something that can leak timing information.
  const char *const volatile *volatile words =
      (const char *const volatile *)wordlist;

  uint32_t partial_word_len = strlen(partial_word), match = 0, found = 0;
  bool precise_match = false;

  // Because we build with -DBIP39_WORDLIST_PADDED=1, exact_str_match is
  // allowed to read longer than the normal strlen of a given word, which has
  // been null-padded to make constant-time comparisons possible.
  if (partial_word_len > BIP39_MAX_WORD_LEN) {
#if DEBUG_LINK && defined(EMULATOR)
    assert(false);
#endif
    return false;
  }

  static uint16_t CONFIDENTIAL permute[2049];
  for (int i = 0; i < 2049; i++) {
    permute[i] = i;
  }
  random_permute_u16(permute, 2048);

  // We don't want the compiler to see through the fact that we're randomly
  // permuting the order of iteration of the next few loops, in case it's
  // smart enough to see through that and remove the permutation, so we tell
  // it we've touched all of memory with some inline asm, and scare it off.
  // This acts as an optimization barrier.
  asm volatile("" ::: "memory");

  // Look for precise matches first (including null termination)
  for (uint32_t volatile i = 0; words[permute[i]] != 0; i++) {
    if (exact_str_match(partial_word, words[permute[i]],
                        partial_word_len + 1)) {
      strlcpy(partial_word, words[permute[i]], CURRENT_WORD_BUF);
      precise_match = true;
    }
  }

  random_permute_u16(permute, 2048);
  asm volatile("" ::: "memory");

  // Followed by partial matches (ignoring null termination)
  for (uint32_t volatile i = 0; words[permute[i]] != 0; i++) {
    if (exact_str_match(partial_word, words[permute[i]], partial_word_len)) {
      match++;
      found = i;
    }
  }

  if (precise_match) {
    memzero(permute, sizeof(permute));
    return true;
  }

  /* Autocomplete if we can */
  if (match == 1) {
    strlcpy(partial_word, words[permute[found]], CURRENT_WORD_BUF);
    memzero(permute, sizeof(permute));
    return true;
  }

  memzero(permute, sizeof(permute));
  return false;
}

/*
 * recovery_cipher_init() - Display standard notification on LCD screen
 *
 * INPUT
 *     - _word_count: Number of words in the recovery sentence
 *     - passphrase_protection: whether to use passphrase protection
 *     - pin_protection: whether to use pin protection
 *     - language: language for device
 *     - label: label for device
 *     - _enforce_wordlist: whether to enforce bip 39 word list
 * OUTPUT
 *     none
 */
void recovery_cipher_init(uint32_t _word_count, bool passphrase_protection,
                          bool pin_protection, const char *language,
                          const char *label, bool _enforce_wordlist,
                          uint32_t _auto_lock_delay_ms, uint32_t _u2f_counter,
                          bool _dry_run) {
  // If word_count is known ahead of time, enforce that it's one of the standard
  // ones:
  if (_word_count && _word_count != 12 && _word_count != 18 &&
      _word_count != 24) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Invalid word count (must be 12, 18 or 24)");
    layoutHome();
    return;
  }

  word_count = _word_count;
  enforce_wordlist = _enforce_wordlist;
  dry_run = _dry_run;

  if (!dry_run) {
    if (pin_protection) {
      if (!change_pin()) {
        recovery_cipher_abort();
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "PINs do not match");
        layoutHome();
        return;
      }
    } else {
      storage_setPin("");
    }

    storage_setPassphraseProtected(passphrase_protection);
    storage_setLanguage(language);
    storage_setLabel(label);
    storage_setAutoLockDelayMs(_auto_lock_delay_ms);
    storage_setU2FCounter(_u2f_counter);
  } else if (!pin_protect("Enter Your PIN")) {
    layoutHome();
    return;
  }

  if (!confirm(ButtonRequestType_ButtonRequest_Other,
               dry_run ? "Recovery Dry Run" : "Recovery",
               "When entering your recovery seed, use the substitution cipher "
               "and check that each word shows up correctly on the screen.")) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Recovery cancelled");
    if (!dry_run) storage_reset();
    layoutHome();
    return;
  }

  /* Clear mnemonic */
  memset(mnemonic, 0, sizeof(mnemonic) / sizeof(char));

  /* Set to recovery cipher mode and generate and show next cipher */
  awaiting_character = true;
  recovery_started = true;
  words_entered = 1;
  next_character();
}

/*
 * next_character() - Randomizes cipher and displays it for next character entry
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void next_character(void) {
  if (!recovery_started) {
    recovery_cipher_abort();
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in Recovery mode");
    layoutHome();
    return;
  }

  /* Scramble cipher */
  strlcpy(cipher, english_alphabet, ENGLISH_ALPHABET_BUF);
  random_permute_char(cipher, strlen(cipher));

  static char CONFIDENTIAL current_word[CURRENT_WORD_BUF];
  get_current_word(current_word);

  /* Words should never be longer than 4 characters */
  if (strlen(current_word) > 4) {
    memzero(current_word, sizeof(current_word));

    recovery_cipher_abort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Words were not entered correctly. Make sure you are using "
                    "the substition cipher.");
    layoutHome();
    return;
  }

  uint32_t word_pos = get_current_word_pos();
  if (word_pos + 1 != words_entered) {
    recovery_cipher_abort();
    fsm_sendFailure(FailureType_Failure_SyntaxError, "Sanity check failed");
    layoutHome();
    return;
  }

  CharacterRequest resp;
  memset(&resp, 0, sizeof(CharacterRequest));

  resp.word_pos = word_pos;
  resp.character_pos = strlen(current_word);

  msg_write(MessageType_MessageType_CharacterRequest, &resp);

  /* Attempt to auto complete if we have at least 3 characters */
  bool auto_completed = false;
  if (strlen(current_word) >= 3) {
    auto_completed = attempt_auto_complete(current_word);
  }

#if DEBUG_LINK
  if (auto_completed) {
    strlcpy(auto_completed_word, current_word, CURRENT_WORD_BUF);
  } else {
    auto_completed_word[0] = '\0';
  }
#endif

  /* Format current word and display it along with cipher */
  static char CONFIDENTIAL formatted_word[CURRENT_WORD_BUF + 10];
  format_current_word(word_pos, current_word, auto_completed, &formatted_word);
  memzero(current_word, sizeof(current_word));

  /* Show cipher and partial word */
  layout_cipher(formatted_word, cipher);
  memzero(formatted_word, sizeof(formatted_word));
}

/*
 * recovery_character() - Decodes character received from host
 *
 * INPUT
 *     - character: string to decode
 * OUTPUT
 *     none
 */
void recovery_character(const char *character) {
  if (!awaiting_character || !recovery_started) {
    recovery_cipher_abort();
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in Recovery mode");
    layoutHome();
    return;
  }

  if (strlen(mnemonic) + 1 > MNEMONIC_BUF - 1) {
    recovery_cipher_abort();
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Too many characters attempted during recovery");
    layoutHome();
    return;
  }

  char *pos = strchr(cipher, character[0]);

  // If not a space and not a legitmate cipher character, send failure.
  if (character[0] != ' ' && pos == NULL) {
    recovery_cipher_abort();
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Character must be from a to z");
    layoutHome();
    return;
  }

  // Count of words we think the user has entered without using the cipher:
  static int uncyphered_word_count = 0;
  static bool definitely_using_cipher = false;
  static CONFIDENTIAL char coded_word[12];
  static CONFIDENTIAL char decoded_word[12];

  if (!mnemonic[0]) {
    uncyphered_word_count = 0;
    definitely_using_cipher = false;
    memzero(coded_word, sizeof(coded_word));
    memzero(decoded_word, sizeof(decoded_word));
  }

  char decoded_character[2] = " ";
  if (character[0] != ' ') {
    // Decode character using cipher if not space
    decoded_character[0] = english_alphabet[(int)(pos - cipher)];

    strlcat(coded_word, character, sizeof(coded_word));
    strlcat(decoded_word, decoded_character, sizeof(decoded_word));

    if (enforce_wordlist && 4 <= strlen(coded_word)) {
      // Check & bail if the user is entering their seed without using the
      // cipher. Note that for each word, this can give false positives about
      // ~0.4% of the time (2048/26^4).

      bool maybe_not_using_cipher = attempt_auto_complete(coded_word);
      bool maybe_using_cipher = attempt_auto_complete(decoded_word);

      if (!maybe_not_using_cipher && maybe_using_cipher) {
        // Decrease the overall false positive rate by detecting that a
        // user has entered a word which is definitely using the
        // cipher.
        definitely_using_cipher = true;
      } else if (maybe_not_using_cipher && !definitely_using_cipher &&
                 MAX_UNCYPHERED_WORDS < uncyphered_word_count++) {
        recovery_cipher_abort();
        fsm_sendFailure(FailureType_Failure_SyntaxError,
                        "Words were not entered correctly. Make sure you are "
                        "using the substition cipher.");
        layoutHome();
        return;
      }
    }
  } else {
    memzero(coded_word, sizeof(coded_word));
    memzero(decoded_word, sizeof(decoded_word));

    if (word_count && words_entered == word_count) {
      strlcat(mnemonic, " ", MNEMONIC_BUF);
      recovery_cipher_finalize();
      return;
    }

    words_entered++;

    if (words_entered > 24 || (word_count && words_entered > word_count)) {
      recovery_cipher_abort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Too many words entered");
      layoutHome();
      return;
    }
  }

  // concat to mnemonic
  strlcat(mnemonic, decoded_character, MNEMONIC_BUF);

  next_character();
}

/*
 * recovery_delete_character() - Deletes previously received recovery character
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void recovery_delete_character(void) {
  if (!recovery_started) {
    recovery_cipher_abort();
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in Recovery mode");
    layoutHome();
    return;
  }

  size_t len = strlen(mnemonic);
  if (len > 0) {
    if (mnemonic[len - 1] == ' ') words_entered--;

    mnemonic[len - 1] = '\0';
  }

  next_character();
}

/*
 * recovery_cipher_finalize() - Finished mnemonic entry
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void recovery_cipher_finalize(void) {
  if (!recovery_started) {
    recovery_cipher_abort();
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    "Not in Recovery mode");
    layoutHome();
    return;
  }

  if (word_count) {
    // If word_count is known ahead of time, also enforce that the correct
    // number of words has been entered:
    if (words_entered != word_count) {
      recovery_cipher_abort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Not enough words entered");
      layoutHome();
      return;
    }
  } else {
    // Otherwise just enforce that the number of words entered is a standard
    // count:
    if (words_entered != 12 && words_entered != 18 && words_entered != 24) {
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      "Invalid word count (must be 12, 18 or 24)");
      layoutHome();
      return;
    }
  }

  static char CONFIDENTIAL new_mnemonic[MNEMONIC_BUF] = "";
  static char CONFIDENTIAL temp_word[CURRENT_WORD_BUF];
  volatile bool auto_completed = true;

  memzero(new_mnemonic, sizeof(new_mnemonic));
  memzero(temp_word, sizeof(temp_word));

  /* Attempt to autocomplete each word */
  char *tok = strtok(mnemonic, " ");

  while (tok) {
    strlcpy(temp_word, tok, CURRENT_WORD_BUF);

    auto_completed &= attempt_auto_complete(temp_word);

    strlcat(new_mnemonic, temp_word, MNEMONIC_BUF);
    strlcat(new_mnemonic, " ", MNEMONIC_BUF);

    tok = strtok(NULL, " ");
  }
  memzero(temp_word, sizeof(temp_word));

  if (!auto_completed && !enforce_wordlist) {
    if (!dry_run) {
      storage_reset();
    }
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Words were not entered correctly. Make sure you are using "
                    "the substition cipher.");
    awaiting_character = false;
    layoutHome();
    return;
  }

  /* Truncate additional space at the end */
  new_mnemonic[MAX(1u, strnlen(new_mnemonic, sizeof(new_mnemonic))) - 1u] = '\0';
  if (!dry_run && (!enforce_wordlist || mnemonic_check(new_mnemonic))) {
    storage_setMnemonic(new_mnemonic);
    memzero(new_mnemonic, sizeof(new_mnemonic));
    if (!enforce_wordlist) {
      // not enforcing => mark storage as imported
      storage_setImported(true);
    }
    storage_commit();
    fsm_sendSuccess("Device recovered");
  } else if (dry_run) {
    bool match =
        storage_isInitialized() && storage_containsMnemonic(new_mnemonic);
    if (match) {
      review(ButtonRequestType_ButtonRequest_Other, "Recovery Dry Run",
             "The seed is valid and MATCHES the one in the device.");
      fsm_sendSuccess("The seed is valid and matches the one in the device.");
    } else if (mnemonic_check(new_mnemonic)) {
      review(ButtonRequestType_ButtonRequest_Other, "Recovery Dry Run",
             "The seed is valid, but DOES NOT MATCH the one in the device.");
      fsm_sendFailure(
          FailureType_Failure_Other,
          "The seed is valid, but does not match the one in the device.");
    } else {
      review(ButtonRequestType_ButtonRequest_Other, "Recovery Dry Run",
             "The seed is INVALID, and DOES NOT MATCH the one in the device.");
      fsm_sendFailure(
          FailureType_Failure_Other,
          "The seed is invalid, and does not match the one in the device.");
    }
    memzero(new_mnemonic, sizeof(new_mnemonic));
  } else {
    session_clear(true);
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    "Invalid mnemonic, are words in correct order?");
    recovery_cipher_abort();
  }

  memzero(new_mnemonic, sizeof(new_mnemonic));
  awaiting_character = false;
  enforce_wordlist = true;
  dry_run = true;
  words_entered = 0;
  word_count = 0;
  memzero(mnemonic, sizeof(mnemonic));
  memzero(cipher, sizeof(cipher));
  layoutHome();
}

#if DEBUG_LINK
/*
 * recovery_get_cipher() - Gets current cipher being show on display
 *
 * INPUT
 *     none
 * OUTPUT
 *     current cipher
 */
const char *recovery_get_cipher(void) { return cipher; }

/*
 * recovery_get_auto_completed_word() - Gets last auto completed word
 *
 * INPUT
 *     none
 * OUTPUT
 *     last auto completed word
 */
const char *recovery_get_auto_completed_word(void) {
  return auto_completed_word;
}
#endif

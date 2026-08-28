/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/dice_input.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/pin_sm.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng.h"
#include "keepkey/rand/rng_health.h"
#include "keepkey/transport/interface.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/rand.h"
#include "trezor/crypto/sha2.h"

#include <stdio.h>

#define _(X) (X)

/* One struct, one owner, one clear. Note what is NOT in here: any call into
 * storage. A staged ceremony has written nothing, so abandoning one cannot
 * leave a half-applied setting behind, and no abort path has anything to
 * remember to undo. */
typedef struct {
  SetupKind kind; /* SETUP_NONE unless armed */
  bool staged;    /* settings staged, not yet armed */
  bool passphrase_protection;
  bool has_language;
  char language[16];
  bool has_label;
  char label[48];
  uint32_t auto_lock_delay_ms;
  uint32_t u2f_counter;
  bool no_backup;
  /* CONFIDENTIAL is a section attribute. It applies to a whole OBJECT of a
     NAMED type, which is why this struct is a typedef and the attribute sits
     on the declaration below — the house pattern, cf. `static SessionState
     CONFIDENTIAL session;` in storage.c. setup_abort() memzeroes the entire
     struct, this PIN included. */
  char pin[PIN_BUF];
} SetupState;

static SetupState CONFIDENTIAL setup;

static uint32_t strength;
static uint8_t CONFIDENTIAL int_entropy[32];
static char CONFIDENTIAL current_words[MNEMONIC_BY_SCREEN_BUF];

/* SHA-256 of the ASCII roll string, shown to the user and exposed over
 * DebugLink. A digest of secret input is not the input, but it is a
 * verification oracle for a 99-symbol space, so it is treated as
 * confidential and cleared as soon as the reset that produced it ends. */
static uint8_t CONFIDENTIAL dice_digest[32];
static bool has_dice_digest = false;

static void dice_digest_clear(void) {
  memzero(dice_digest, sizeof(dice_digest));
  has_dice_digest = false;
}

bool setup_isArmed(void) { return setup.kind != SETUP_NONE; }

bool setup_isArmedAs(SetupKind kind) {
  return kind != SETUP_NONE && setup.kind == kind;
}

void setup_abort(void) {
  /* The recovery half owns its own word buffers. Clearing them is a memzero
   * too; like everything here it touches no storage. */
  recovery_cipher_reset();
  mnemonic_clear();

  memzero(&setup, sizeof(setup));
  memzero(int_entropy, sizeof(int_entropy));
  memzero(current_words, sizeof(current_words));
  /* reset_entropy() receives its generated sentence from bip39.c's static
   * `mnemo` buffer.  A cancelled/error ceremony has no owner for that secret,
   * so the common abort path must clear it along with the setup scratch. */
  mnemonic_clear();
  /* The roll digest is ceremony state like the rest: it only describes the
   * reset that produced it, and leaving it live would keep serving it over
   * DebugLink for the rest of the boot. */
  dice_digest_clear();
  strength = 0;
}

bool setup_require(SetupKind kind, const char* errmsg) {
  if (setup_isArmedAs(kind)) return true;

  /* Out of sequence. Kill the ceremony rather than leaving it armed for the
   * next attempt: the host can already end one with Cancel, so there is
   * nothing to protect by keeping it. */
  setup_abort();
  fsm_sendFailure(FailureType_Failure_UnexpectedMessage, errmsg);
  layoutHome();
  return false;
}

bool setup_stage(bool passphrase_protection, const char* language,
                 const char* label, uint32_t auto_lock_delay_ms,
                 uint32_t u2f_counter, bool no_backup) {
  if (setup_isArmed()) {
    /* One ceremony at a time. This is where issue #429 dies: a RecoveryDevice
     * sent in the middle of a ResetDevice is refused instead of quietly
     * overwriting the settings the user is in the middle of choosing. */
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Device is in the middle of setup"));
    layoutHome();
    return false;
  }

  setup_abort(); /* start from a known-zero staging area */

  setup.passphrase_protection = passphrase_protection;
  setup.auto_lock_delay_ms = auto_lock_delay_ms;
  setup.u2f_counter = u2f_counter;
  setup.no_backup = no_backup;

  /* storage_setLanguage()/storage_setLabel() ignore a NULL, so a host that
   * omits the field must leave the stored value alone. Record the absence
   * rather than staging an empty string. */
  if (language) {
    setup.has_language = true;
    strlcpy(setup.language, language, sizeof(setup.language));
  }
  if (label) {
    setup.has_label = true;
    strlcpy(setup.label, label, sizeof(setup.label));
  }

  setup.staged = true;
  return true;
}

bool setup_stagePin(bool pin_protection) {
  if (!setup.staged) return false;

  if (!pin_protection) {
    /* The empty PIN is a choice like any other: stage it, do not apply it. */
    memzero(setup.pin, sizeof(setup.pin));
    return true;
  }

  return change_pin_staged(setup.pin, sizeof(setup.pin));
}

void setup_arm(SetupKind kind) {
  setup.kind = setup.staged ? kind : SETUP_NONE;
}

void setup_commit(const char* mnemonic, bool imported) {
  /* The ordering below is load-bearing. storage_setPin() derives the storage
   * key that storage_commit() encrypts the secrets with, so it has to run
   * before storage_setMnemonic(). Do not reorder. */
  storage_setPin(setup.pin);
  storage_setPassphraseProtected(setup.passphrase_protection);
  if (setup.has_language) storage_setLanguage(setup.language);
  if (setup.has_label) storage_setLabel(setup.label);
  storage_setAutoLockDelayMs(setup.auto_lock_delay_ms);
  storage_stageU2FCounter(setup.u2f_counter);
  if (setup.no_backup) storage_setNoBackup();

  storage_setMnemonic(mnemonic);
  if (imported) storage_setImported(true);
  mnemonic_clear();

  /* Disarm before the flash write. The ceremony is over at this point, and
   * storage_commit() aborts any ceremony still armed when it runs. */
  setup_abort();
  storage_commit();
}

/* Shared paginated-mnemonic display scratch — see reset.h for the contract
 * (also used by the BIP-85 flow; each user zeroes at entry and exit). */
char CONFIDENTIAL mnemonic_scratch_tokened[TOKENED_MNEMONIC_BUF];
char CONFIDENTIAL mnemonic_scratch_formatted[MAX_PAGES][FORMATTED_MNEMONIC_BUF];
char CONFIDENTIAL mnemonic_scratch_display[FORMATTED_MNEMONIC_BUF];
char CONFIDENTIAL mnemonic_scratch_word[MAX_WORD_LEN + ADDITIONAL_WORD_PAD];

void reset_init(uint32_t _strength, bool passphrase_protection,
                bool pin_protection, const char* language, const char* label,
                bool _no_backup, uint32_t _auto_lock_delay_ms,
                uint32_t _u2f_counter, bool dice_entropy) {
  if (_strength != 128 && _strength != 192 && _strength != 256) {
    fsm_sendFailure(
        FailureType_Failure_SyntaxError,
        _("Invalid mnemonic strength (has to be 128, 192 or 256 bits)"));
    layoutHome();
    return;
  }

  /* Nothing below this line writes storage. Everything the host asked for is
   * staged, and stays staged until reset_entropy() reaches setup_commit().
   * Returning early from any of the screens below therefore rolls the whole
   * ceremony back by doing nothing at all: setup.kind is still SETUP_NONE,
   * so no later message can consume what was staged.
   *
   * This is also the whole of the abandoned-ceremony fix. There is no
   * separate awaiting_entropy flag left to get out of step with: the ONLY
   * armed-ness is setup.kind, it is set by the single setup_arm() at the
   * bottom of this function -- after every screen, dice included -- and
   * reset_entropy() is gated on it through setup_require(). An abort at any
   * screen therefore leaves nothing armed for a later EntropyAck to consume,
   * and setup_stage() refuses outright to start a second ceremony on top of
   * an armed one, so an in-flight reset's entropy can never be overwritten
   * by a re-entrant one. */
  if (!setup_stage(passphrase_protection, language, label, _auto_lock_delay_ms,
                   _u2f_counter, _no_backup)) {
    return;
  }

  strength = _strength;

  if (_no_backup) {
    // Double confirm, since this is a feature for advanced users only, and
    // there is risk of loss of funds if this mode is used incorrectly
    // (i.e. multisig is an absolute must with this scheme).
    if (!confirm(ButtonRequestType_ButtonRequest_Other, _("WARNING"),
                 _("The 'No Backup' option was selected.\n"
                   "Recovery sentence will *NOT* be shown,\n"
                   "and recovery will be IMPOSSIBLE.\n")) ||
        !confirm(ButtonRequestType_ButtonRequest_Other, _("WARNING"),
                 _("The 'No Backup' option was selected.\n\n"
                   "I understand, and accept the risks.\n"))) {
      setup_abort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Reset cancelled"));
      layoutHome();
      return;
    }
  }

  /* Asked here rather than only inside the draw below so the host gets a real
   * error message instead of a halted device: this is the one key-material path
   * with somewhere to report a failure to.
   *
   * This does NOT prove the generator is unpredictable; see the scope note at
   * the top of lib/rand/rng_health.c. It proves it is present and not stuck. */
  if (!rng_health_check()) {
    /* FirmwareError, not SyntaxError/Other: nothing about the request is
     * wrong. The device's own entropy source failed its self-test, which is a
     * hardware/firmware fault the host cannot correct by retrying. */
    setup_abort();
    fsm_sendFailure(
        FailureType_Failure_FirmwareError,
        _("Random number generator self-test failed; cannot create a wallet"));
    layoutHome();
    return;
  }

  /* The gate above and this draw are deliberately not separable: the check
   * cannot be edited out of this function while leaving the draw behind. */
  if (!random_buffer_checked(int_entropy, 32)) {
    /* The draw may have written part of int_entropy before failing. */
    setup_abort();
    fsm_sendFailure(
        FailureType_Failure_FirmwareError,
        _("Random number generator self-test failed; cannot create a wallet"));
    layoutHome();
    return;
  }

  /* Dice fold in before EntropyRequest, so the host contribution arrives
   * strictly after the device has committed to its own.
   *
   * They are deliberately NOT displayed. An earlier version of this code
   * showed the mixed internal entropy on the OLED and called it a
   * verifiable commitment; that was wrong. A host that supplies
   * ext_entropy and reads that screen once computes
   * SHA256(shown || ext_entropy) -- the seed pre-image -- and dice change
   * nothing about it, because the displayed value is already post-mix. The
   * roll digest below is safe by contrast: it is a hash of the user's own
   * input, not of seed material.
   *
   * ResetDevice.display_random stays in the wire schema and is ignored by
   * fsm_msgResetDevice(), which is why the old "Can't show internal entropy
   * when backup is skipped" syntax check is gone: there is no longer an
   * entropy screen for it to be inconsistent with.
   *
   * The digest needs no clear here -- setup_stage() above ran setup_abort(),
   * which zeroes it. */
  if (dice_entropy) {
    static char CONFIDENTIAL dice_rolls[DICE_MAX_ROLLS];
    static char CONFIDENTIAL digest_hex[17];
    uint32_t rolls_needed = dice_rolls_for_strength(strength);

    if (!dice_input_collect(dice_rolls, rolls_needed)) {
      memzero(dice_rolls, sizeof(dice_rolls));
      /* setup_abort() is the whole rollback -- staged settings, int_entropy,
       * strength, roll digest. Load-bearing: the tiny-message pump that
       * accepted the Cancel/Initialize does not dispatch fsm_msgCancel, so
       * nothing else has aborted the ceremony at this point. */
      setup_abort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Reset cancelled"));
      layoutHome();
      return;
    }

    sha256_Raw((const uint8_t*)dice_rolls, rolls_needed, dice_digest);
    has_dice_digest = true;

    data2hex(dice_digest, 8, digest_hex);
    bool confirmed =
        confirm(ButtonRequestType_ButtonRequest_DiceRoll, _("Dice Rolls"),
                _("%lu rolls recorded.\nDigest: %s"),
                (unsigned long)rolls_needed, digest_hex);
    memzero(digest_hex, sizeof(digest_hex));
    if (!confirmed) {
      memzero(dice_rolls, sizeof(dice_rolls));
      setup_abort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Reset cancelled"));
      layoutHome();
      return;
    }

    dice_mix(int_entropy, dice_rolls, rolls_needed);
    memzero(dice_rolls, sizeof(dice_rolls));
  }

  if (!setup_stagePin(pin_protection)) {
    /* Clears the roll digest along with the staged settings and entropy. */
    setup_abort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    _("PINs do not match"));
    layoutHome();
    return;
  }

  EntropyRequest resp;
  memset(&resp, 0, sizeof(EntropyRequest));
  /* Arm last, and only here: from this statement on an EntropyAck is in
   * sequence, and nothing else is. */
  setup_arm(SETUP_RESET);
  msg_write(MessageType_MessageType_EntropyRequest, &resp);
}

void reset_entropy(const uint8_t* ext_entropy, uint32_t len) {
  if (!setup_require(SETUP_RESET, _("Not in Reset mode"))) {
    return;
  }

  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, int_entropy, 32);
  sha256_Update(&ctx, ext_entropy, len);
  sha256_Final(&ctx, int_entropy);

  const char* temp_mnemonic = mnemonic_from_data(int_entropy, strength / 8);

  memzero(int_entropy, sizeof(int_entropy));

  if (setup.no_backup) {
    /* Consent for this path is the two WARNING holds taken during the same
     * ceremony, in reset_init(). */
    setup_commit(temp_mnemonic, /*imported=*/false);
    fsm_sendSuccess(_("Device reset"));
    goto exit;
  } else {
    if (!confirm(ButtonRequestType_ButtonRequest_Other,
                 _("Recovery Seed Backup"),
                 "This recovery seed will only be shown ONCE. "
                 "Please write it down carefully,\n"
                 "and DO NOT share it with anyone. ")) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Reset cancelled"));
      /* storage_reset() used to run here. Nothing was written, so there is
       * nothing to reset -- and a host-reachable wipe is not a rollback. */
      setup_abort();
      layoutHome();
      goto exit;
    }
  }

  /*
   * Format mnemonic for user review. Display scratch is the set shared with
   * the BIP-85 flow (see reset.h) — zero it at entry: the format loop below
   * depends on empty page strings, and a prior user may have aborted.
   */
  uint32_t word_count = 0, page_count = 0;
  static char CONFIDENTIAL
      mnemonic_by_screen[MAX_PAGES][MNEMONIC_BY_SCREEN_BUF];
  char* tokened_mnemonic = mnemonic_scratch_tokened;
  char (*formatted_mnemonic)[FORMATTED_MNEMONIC_BUF] =
      mnemonic_scratch_formatted;
  char* mnemonic_display = mnemonic_scratch_display;
  char* formatted_word = mnemonic_scratch_word;
  memzero(mnemonic_scratch_tokened, sizeof(mnemonic_scratch_tokened));
  memzero(mnemonic_scratch_formatted, sizeof(mnemonic_scratch_formatted));
  memzero(mnemonic_scratch_display, sizeof(mnemonic_scratch_display));
  memzero(mnemonic_scratch_word, sizeof(mnemonic_scratch_word));
  memzero(mnemonic_by_screen, sizeof(mnemonic_by_screen));

  strlcpy(tokened_mnemonic, temp_mnemonic, TOKENED_MNEMONIC_BUF);

  char* tok = strtok(tokened_mnemonic, " ");

  while (tok) {
    snprintf(formatted_word, MAX_WORD_LEN + ADDITIONAL_WORD_PAD,
             (word_count & 1) ? "%lu.%s\n" : "%lu.%s",
             (unsigned long)(word_count + 1), tok);

    /* Check that we have enough room on display to show word */
    snprintf(mnemonic_display, FORMATTED_MNEMONIC_BUF, "%s   %s",
             formatted_mnemonic[page_count], formatted_word);

    if (calc_str_line(get_body_font(), mnemonic_display, BODY_WIDTH) > 3) {
      page_count++;

      if (MAX_PAGES <= page_count) {
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Too many pages of mnemonic words"));
        setup_abort();
        goto exit;
      }

      snprintf(mnemonic_display, FORMATTED_MNEMONIC_BUF, "%s   %s",
               formatted_mnemonic[page_count], formatted_word);
    }

    strlcpy(formatted_mnemonic[page_count], mnemonic_display,
            FORMATTED_MNEMONIC_BUF);

    /* Save mnemonic for each screen */
    if (strlen(mnemonic_by_screen[page_count]) == 0) {
      strlcpy(mnemonic_by_screen[page_count], tok, MNEMONIC_BY_SCREEN_BUF);
    } else {
      strlcat(mnemonic_by_screen[page_count], " ", MNEMONIC_BY_SCREEN_BUF);
      strlcat(mnemonic_by_screen[page_count], tok, MNEMONIC_BY_SCREEN_BUF);
    }

    tok = strtok(NULL, " ");
    word_count++;
  }

  // Switch from 0-indexing to 1-indexing
  page_count++;

  display_constant_power(true);

  /* Have user confirm mnemonic is sets of 12 words */
  for (uint32_t current_page = 0; current_page < page_count; current_page++) {
    char title[MEDIUM_STR_BUF] = _("Backup");

    /* make current screen mnemonic available via debuglink */
    strlcpy(current_words, mnemonic_by_screen[current_page],
            MNEMONIC_BY_SCREEN_BUF);

    if (page_count > 1) {
      /* snprintf: 20 + 10 (%d) + 1 (NULL) = 31 */
      snprintf(title, MEDIUM_STR_BUF, _("Backup %" PRIu32 "/%" PRIu32 ""),
               current_page + 1, page_count);
    }

    /* Keep the legacy one-request-per-group host protocol while paging the
     * narrower physical OLED layout locally inside that request. */
    if (!confirm_constant_power_paged(
            ButtonRequestType_ButtonRequest_ConfirmWord, title,
            formatted_mnemonic[current_page])) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Reset cancelled"));
      setup_abort();
      goto exit;
    }
  }

  /* Every page was held through. This is the commit point: the settings the
   * user chose during THIS ceremony and the seed land together, or neither
   * lands. */
  setup_commit(temp_mnemonic, /*imported=*/false);
  fsm_sendSuccess(_("Device reset"));

exit:
  /* The roll digest is cleared by setup_abort(); every path that reaches
   * here has already run it, directly or through setup_commit(). */
  memzero(&ctx, sizeof(ctx));
  memzero(mnemonic_scratch_tokened, sizeof(mnemonic_scratch_tokened));
  memzero(mnemonic_by_screen, sizeof(mnemonic_by_screen));
  memzero(mnemonic_scratch_formatted, sizeof(mnemonic_scratch_formatted));
  memzero(mnemonic_scratch_display, sizeof(mnemonic_scratch_display));
  memzero(mnemonic_scratch_word, sizeof(mnemonic_scratch_word));
  layoutHome();
}

#if DEBUG_LINK
uint32_t reset_get_int_entropy(uint8_t* entropy) {
  memcpy(entropy, int_entropy, 32);
  return 32;
}

const char* reset_get_word(void) { return current_words; }

uint32_t reset_get_dice_digest(uint8_t* digest) {
  if (!has_dice_digest) {
    return 0;
  }
  memcpy(digest, dice_digest, 32);
  return 32;
}
#endif

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

/* SHA-256 of the ASCII rolls; in ONLY mode it IS the seed material. */
static uint8_t CONFIDENTIAL dice_digest[32];
static bool has_dice_digest = false;

/* Host-selected, device-confirmed. setup_abort() clears it so an abandoned
 * ceremony cannot leave it armed. */
static DiceMode dice_mode = DICE_MODE_NONE;

static void dice_digest_clear(void) {
  memzero(dice_digest, sizeof(dice_digest));
  has_dice_digest = false;
  dice_mode = DICE_MODE_NONE;
}

static bool show_mnemonic_pages(const char* mnemonic, const char* title_base,
                                ButtonRequestType type);

bool setup_isArmed(void) { return setup.kind != SETUP_NONE; }

bool setup_isArmedAs(SetupKind kind) {
  return kind != SETUP_NONE && setup.kind == kind;
}

void setup_abort(void) {
  /* Never leave the last secret page in the canvas or debug state. */
  if (dice_mode != DICE_MODE_NONE) {
    layout_clear();
#if DEBUG_LINK
    confirm_debug_clear();
#endif
  }
  /* The recovery half owns its own word buffers. Clearing them is a memzero
   * too; like everything here it touches no storage. */
  recovery_cipher_reset();

  memzero(&setup, sizeof(setup));
  memzero(int_entropy, sizeof(int_entropy));
  memzero(current_words, sizeof(current_words));
  mnemonic_scratch_wipe();
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

bool setup_commit(SetupKind kind, const char* mnemonic, bool imported) {
  if (!setup_require(kind, "Setup ceremony was aborted")) return false;
  /* storage_commit() would decline these: never report a false Success. */
  if (storage_isBitcoinOnlyLocked() || storage_isFirmwareTooOld()) {
    setup_abort();
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Storage is locked for this firmware. Use Wipe first."));
    layoutHome();
    return false;
  }
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
  return true;
}

void reset_init(uint32_t _strength, bool passphrase_protection,
                bool pin_protection, const char* language, const char* label,
                bool _no_backup, uint32_t _auto_lock_delay_ms,
                uint32_t _u2f_counter, bool dice_entropy, bool dice_only) {
  if (_strength != 128 && _strength != 192 && _strength != 256) {
    fsm_sendFailure(
        FailureType_Failure_SyntaxError,
        _("Invalid mnemonic strength (has to be 128, 192 or 256 bits)"));
    layoutHome();
    return;
  }

  if (dice_only && !dice_entropy) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("dice_only requires dice_entropy"));
    layoutHome();
    return;
  }

  /* Dice output is only meaningful checked against the backup words. */
  if (dice_entropy && _no_backup) {
    fsm_sendFailure(FailureType_Failure_SyntaxError,
                    _("Dice entropy cannot be combined with no_backup"));
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
  /* Set before the draw: DebugLink must never expose dice entropy. */
  dice_mode = dice_entropy ? (dice_only ? DICE_MODE_ONLY : DICE_MODE_MIXED)
                           : DICE_MODE_NONE;

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

  /* Dice ceremony; the device names the host-selected mode for consent.
   * Verifiable offline: host EntropyAck bytes never enter the derivation.
   *
   *   MIXED: seed = SHA256d(tag || device_draw || SHA256(tag2 || rolls)); the
   *          draw is shown as 24 words BEFORE the rolls, so it cannot steer.
   *   ONLY:  seed = SHA256(rolls).
   *
   * Showing the draw is safe only because the other half is offline dice.
   *
   * The roll digest is shown in full; in ONLY mode it IS the seed material.
   *
   * No clear needed: setup_stage() above ran setup_abort(). */
  if (dice_entropy) {
    static char CONFIDENTIAL dice_rolls[DICE_MAX_ROLLS];
    uint32_t rolls_needed = dice_rolls_for_strength(strength);

    bool consented =
        dice_only
            ? confirm(ButtonRequestType_ButtonRequest_DiceRoll, _("Dice Only"),
                      _("Seed from %lu rolls ALONE, no device randomness. "
                        "Verifiable offline."),
                      (unsigned long)rolls_needed)
            : confirm(ButtonRequestType_ButtonRequest_DiceRoll,
                      _("Dice + Device"),
                      _("Next: 24 entropy words, NOT a backup. Copy "
                        "them, then roll %lu dice."),
                      (unsigned long)rolls_needed);
    if (!consented) {
      setup_abort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Reset cancelled"));
      layoutHome();
      return;
    }

    if (dice_mode == DICE_MODE_MIXED) {
      /* Always the full 32-byte draw; mnemonic_clear() on every path. */
      bool shown =
          show_mnemonic_pages(mnemonic_from_data(int_entropy, 32), _("Entropy"),
                              ButtonRequestType_ButtonRequest_DiceRoll);
      mnemonic_clear();
      if (!shown) {
        setup_abort();
        layoutHome();
        return;
      }
    }

    memzero(current_words, sizeof(current_words));
    if (!dice_input_collect(dice_rolls, rolls_needed)) {
      memzero(dice_rolls, sizeof(dice_rolls));
      /* Load-bearing: the tiny-message pump never ran fsm_msgCancel. */
      setup_abort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Reset cancelled"));
      layoutHome();
      return;
    }

    if (dice_rolls_look_biased(dice_rolls, rolls_needed)) {
      memzero(dice_rolls, sizeof(dice_rolls));
      setup_abort();
      fsm_sendFailure(FailureType_Failure_SyntaxError,
                      _("Dice rolls look biased: one face came up too often"));
      layoutHome();
      return;
    }

    sha256_Raw((const uint8_t*)dice_rolls, rolls_needed, dice_digest);
    has_dice_digest = true;

    /* Reuses CONFIDENTIAL current_words (idle here) to save SRAM. */
    {
      char hex[4][17];
      data2hex(dice_digest, 8, hex[0]);
      data2hex(dice_digest + 8, 8, hex[1]);
      data2hex(dice_digest + 16, 8, hex[2]);
      data2hex(dice_digest + 24, 8, hex[3]);
      snprintf(current_words, sizeof(current_words),
               _("%lu rolls. Digest, SECRET:\n%s %s\n%s %s"),
               (unsigned long)rolls_needed, hex[0], hex[1], hex[2], hex[3]);
      memzero(hex, sizeof(hex));
    }
    bool confirmed =
        confirm_constant_power_paged(ButtonRequestType_ButtonRequest_DiceRoll,
                                     _("Dice Rolls"), current_words);
    memzero(current_words, sizeof(current_words));
    if (!confirmed) {
      memzero(dice_rolls, sizeof(dice_rolls));
      setup_abort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Reset cancelled"));
      layoutHome();
      return;
    }

    if (dice_mode == DICE_MODE_ONLY) {
      dice_derive_only(dice_rolls, rolls_needed, int_entropy);
    } else {
      dice_derive_mixed(int_entropy, dice_rolls, rolls_needed, int_entropy);
    }
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
  note_workflow_progress();
  msg_write(MessageType_MessageType_EntropyRequest, &resp);
}

/* Shared mnemonic display scratch; contract in reset.h. */
char CONFIDENTIAL mnemonic_scratch_tokened[TOKENED_MNEMONIC_BUF];
char CONFIDENTIAL mnemonic_scratch_formatted[MAX_PAGES][FORMATTED_MNEMONIC_BUF];
char CONFIDENTIAL mnemonic_scratch_display[FORMATTED_MNEMONIC_BUF];
char CONFIDENTIAL mnemonic_scratch_word[MAX_WORD_LEN + ADDITIONAL_WORD_PAD];

void mnemonic_scratch_wipe(void) {
  memzero(mnemonic_scratch_tokened, sizeof(mnemonic_scratch_tokened));
  memzero(mnemonic_scratch_formatted, sizeof(mnemonic_scratch_formatted));
  memzero(mnemonic_scratch_display, sizeof(mnemonic_scratch_display));
  memzero(mnemonic_scratch_word, sizeof(mnemonic_scratch_word));
}

/* One ButtonRequest per page. On cancel/overflow sends Failure and returns
 * false; the caller owns rollback. Scratch zeroed at entry and every exit. */
static bool show_mnemonic_pages(const char* mnemonic, const char* title_base,
                                ButtonRequestType type) {
  uint32_t word_count = 0, page_count = 0;
  static char CONFIDENTIAL
      mnemonic_by_screen[MAX_PAGES][MNEMONIC_BY_SCREEN_BUF];
  bool ok = false;

  mnemonic_scratch_wipe();
  memzero(mnemonic_by_screen, sizeof(mnemonic_by_screen));

  if (mnemonic == NULL) {
    fsm_sendFailure(FailureType_Failure_Other, _("No mnemonic to display"));
    goto done;
  }

  strlcpy(mnemonic_scratch_tokened, mnemonic, TOKENED_MNEMONIC_BUF);

  char* tok = strtok(mnemonic_scratch_tokened, " ");

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
        fsm_sendFailure(FailureType_Failure_Other,
                        _("Too many pages of mnemonic words"));
        goto done;
      }

      snprintf(mnemonic_scratch_display, FORMATTED_MNEMONIC_BUF, "%s   %s",
               mnemonic_scratch_formatted[page_count], mnemonic_scratch_word);
    }

    strlcpy(mnemonic_scratch_formatted[page_count], mnemonic_scratch_display,
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
    char title[MEDIUM_STR_BUF];
    strlcpy(title, title_base, MEDIUM_STR_BUF);

    strlcpy(current_words, mnemonic_by_screen[current_page],
            MNEMONIC_BY_SCREEN_BUF);

    if (page_count > 1) {
      snprintf(title, MEDIUM_STR_BUF, _("%s %" PRIu32 "/%" PRIu32 ""),
               title_base, current_page + 1, page_count);
    }

    /* Keep the legacy one-request-per-group host protocol while paging the
     * narrower physical OLED layout locally inside that request. */
    if (!confirm_constant_power_paged(
            type, title, mnemonic_scratch_formatted[current_page])) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Reset cancelled"));
      goto done;
    }
  }

  ok = true;

done:
  mnemonic_scratch_wipe();
  memzero(mnemonic_by_screen, sizeof(mnemonic_by_screen));
  return ok;
}

void reset_entropy(const uint8_t* ext_entropy, uint32_t len) {
  if (!setup_require(SETUP_RESET, _("Not in Reset mode"))) {
    return;
  }

  note_workflow_progress();

  SHA256_CTX ctx;
  memzero(&ctx, sizeof(ctx));
  /* Dice: int_entropy is already the full derivation. Host bytes must NOT
   * be mixed in (would break the offline check); not re-hashed. */
  if (dice_mode == DICE_MODE_NONE) {
    sha256_Init(&ctx);
    sha256_Update(&ctx, int_entropy, 32);
    sha256_Update(&ctx, ext_entropy, len);
    sha256_Final(&ctx, int_entropy);
  }

  const char* temp_mnemonic = mnemonic_from_data(int_entropy, strength / 8);

  memzero(int_entropy, sizeof(int_entropy));

  if (setup.no_backup) {
    if (!setup_commit(SETUP_RESET, temp_mnemonic, /*imported=*/false))
      goto exit;
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
      /* Nothing was written; a host-reachable wipe is not a rollback. */
      setup_abort();
      layoutHome();
      goto exit;
    }
  }

  if (!show_mnemonic_pages(temp_mnemonic, _("Backup"),
                           ButtonRequestType_ButtonRequest_ConfirmWord)) {
    setup_abort();
    goto exit;
  }

  /* Every page was held through. This is the commit point: the settings the
   * user chose during THIS ceremony and the seed land together, or neither
   * lands. */
  if (!setup_commit(SETUP_RESET, temp_mnemonic, /*imported=*/false)) goto exit;
  fsm_sendSuccess(_("Device reset"));

exit:
  /* The roll digest is cleared by setup_abort(); every path that reaches
   * here has already run it, directly or through setup_commit(). */
  memzero(&ctx, sizeof(ctx));
  mnemonic_clear();
  layoutHome();
}

#if DEBUG_LINK
bool reset_debug_is_private(void) { return dice_mode != DICE_MODE_NONE; }

uint32_t reset_get_int_entropy(uint8_t* entropy) {
  if (dice_mode != DICE_MODE_NONE) return 0;
  memcpy(entropy, int_entropy, 32);
  return 32;
}

const char* reset_get_word(void) {
  return reset_debug_is_private() ? "" : current_words;
}

uint32_t reset_get_dice_digest(uint8_t* digest) {
  if (reset_debug_is_private() || !has_dice_digest) {
    return 0;
  }
  memcpy(digest, dice_digest, 32);
  return 32;
}
#endif

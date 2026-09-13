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

/* Which dice derivation this ceremony uses. Selected by the host in
 * ResetDevice (dice_entropy / dice_only) and confirmed on the device by the
 * consent screen in reset_init() before anything runs. Cleared with the
 * digest by setup_abort(), so an abandoned ceremony cannot leave it armed. */
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

bool setup_commit(SetupKind kind, const char* mnemonic, bool imported) {
  if (!setup_require(kind, "Setup ceremony was aborted")) return false;
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

/* Shared paginated-mnemonic display scratch — see reset.h for the contract
 * (also used by the BIP-85 flow; each user zeroes at entry and exit). */
char CONFIDENTIAL mnemonic_scratch_tokened[TOKENED_MNEMONIC_BUF];
char CONFIDENTIAL mnemonic_scratch_formatted[MAX_PAGES][FORMATTED_MNEMONIC_BUF];
char CONFIDENTIAL mnemonic_scratch_display[FORMATTED_MNEMONIC_BUF];
char CONFIDENTIAL mnemonic_scratch_word[MAX_WORD_LEN + ADDITIONAL_WORD_PAD];

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

  /* The dice modes exist to be checked against the backup words. A reset that
   * never shows them has nothing to verify, and would put seed material (the
   * digest, the entropy words) on the screen under a WARNING that recovery is
   * impossible. Refused, as display_random with no_backup was. */
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

  /* Dice ceremony. The host selects the mode in ResetDevice so a wallet can
   * explain what is coming before anything starts; the device then shows a
   * consent screen naming the mode it was asked for, so a host cannot pick
   * one silently. (It is a confirm, not a selector: on a one-button device a
   * confirm() ends only by hold or by the host's Cancel, and "cancel the
   * reset" is exactly the right answer to a mode the user did not want.)
   * Both modes are verifiable offline: nothing enters the derivation that
   * the user does not hold, and the host's EntropyAck bytes are consumed and
   * dropped in reset_entropy().
   *
   *   MIXED: seed = SHA256d(tag || device_draw || SHA256(tag2 || rolls)).
   *          The device draw is shown as 24 BIP-39 words BEFORE the rolls
   *          are entered, so it is committed before the device has seen them
   *          and cannot be chosen to steer the result. The user copies the
   *          words down; with those and the rolls they recompute the seed.
   *   ONLY:  seed = SHA256(rolls). The device draw is discarded. Coldcard's
   *          Dice-Rolls-Only, byte for byte.
   *
   * Showing the device draw here is safe for the reason it was unsafe under
   * the old ResetDevice.display_random screen. That screen revealed the same
   * 32 bytes while the OTHER half was still host-supplied and uncommitted,
   * so anyone who read it and knew ext_entropy held the seed pre-image. Here
   * the other half is dice the user rolls after the words are shown and that
   * never cross a wire; the host contributes nothing. display_random stays on
   * the wire and is ignored. Trezor removed the same inherited feature for the
   * same reason (PR #4119).
   *
   * The roll digest is shown in full. In ONLY mode it is the seed material
   * itself; in both it is the commitment the offline verifier checks.
   *
   * The digest and mode need no clear here -- setup_stage() above ran
   * setup_abort(), which zeroes them. */
  if (dice_entropy) {
    static char CONFIDENTIAL dice_rolls[DICE_MAX_ROLLS];
    uint32_t rolls_needed = dice_rolls_for_strength(strength);

    dice_mode = dice_only ? DICE_MODE_ONLY : DICE_MODE_MIXED;
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
      /* setup_abort() is the whole rollback -- staged settings, int_entropy,
       * strength, roll digest, mode. */
      setup_abort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Reset cancelled"));
      layoutHome();
      return;
    }

    if (dice_mode == DICE_MODE_MIXED) {
      /* All 32 bytes, always 24 words, whatever strength was requested: the
       * verifier needs the whole draw. mnemonic_from_data() returns bip39.c's
       * static buffer; the pager copies it before anything else runs, and
       * mnemonic_clear() zeroes it afterwards on every path. */
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

    /* Empty for the duration of roll entry, so a DebugLink reader can tell
     * the roll screen apart from the word pages that may precede it. */
    memzero(current_words, sizeof(current_words));
    if (!dice_input_collect(dice_rolls, rolls_needed)) {
      memzero(dice_rolls, sizeof(dice_rolls));
      /* Load-bearing: the tiny-message pump that accepted the
       * Cancel/Initialize does not dispatch fsm_msgCancel, so nothing else
       * has aborted the ceremony at this point. */
      setup_abort();
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Reset cancelled"));
      layoutHome();
      return;
    }

    if (dice_rolls_look_biased(dice_rolls, rolls_needed)) {
      memzero(dice_rolls, sizeof(dice_rolls));
      setup_abort();
      fsm_sendFailure(
          FailureType_Failure_SyntaxError,
          _("Dice rolls look biased: one face exceeds 30% of the rolls"));
      layoutHome();
      return;
    }

    sha256_Raw((const uint8_t*)dice_rolls, rolls_needed, dice_digest);
    has_dice_digest = true;

    /* The digest page is formatted into current_words: 265 bytes, already
     * CONFIDENTIAL, and idle between roll entry and the backup pager. A new
     * static buffer here cost the full 7.15 image its 16 KiB SRAM reserve,
     * which sits within a few dozen bytes of the linker floor. Under
     * DEBUG_LINK reset_get_word() returns this text while the page is up; the
     * digest is already exposed there. */
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
  msg_write(MessageType_MessageType_EntropyRequest, &resp);
}

/* Page \a mnemonic under one ButtonRequest per screen, exposing each screen's
 * words through reset_get_word() for DebugLink. Used for the backup words
 * and, in the dice MIXED mode, for the device-entropy words the user copies
 * down to verify the seed offline. Sends its own Failure and returns false
 * when the user cancels or the sentence does not fit; the caller owns the
 * ceremony rollback. The display scratch is the set shared with the BIP-85
 * flow (see reset.h): zeroed at entry, because the format loop depends on
 * empty page strings and a prior user may have aborted, and on every exit. */
static bool show_mnemonic_pages(const char* mnemonic, const char* title_base,
                                ButtonRequestType type) {
  uint32_t word_count = 0, page_count = 0;
  static char CONFIDENTIAL
      mnemonic_by_screen[MAX_PAGES][MNEMONIC_BY_SCREEN_BUF];
  char* tokened_mnemonic = mnemonic_scratch_tokened;
  char (*formatted_mnemonic)[FORMATTED_MNEMONIC_BUF] =
      mnemonic_scratch_formatted;
  char* mnemonic_display = mnemonic_scratch_display;
  char* formatted_word = mnemonic_scratch_word;
  bool ok = false;

  memzero(mnemonic_scratch_tokened, sizeof(mnemonic_scratch_tokened));
  memzero(mnemonic_scratch_formatted, sizeof(mnemonic_scratch_formatted));
  memzero(mnemonic_scratch_display, sizeof(mnemonic_scratch_display));
  memzero(mnemonic_scratch_word, sizeof(mnemonic_scratch_word));
  memzero(mnemonic_by_screen, sizeof(mnemonic_by_screen));

  if (mnemonic == NULL) {
    fsm_sendFailure(FailureType_Failure_Other, _("No mnemonic to display"));
    goto done;
  }

  strlcpy(tokened_mnemonic, mnemonic, TOKENED_MNEMONIC_BUF);

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
        goto done;
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
    char title[MEDIUM_STR_BUF];
    strlcpy(title, title_base, MEDIUM_STR_BUF);

    /* make current screen mnemonic available via debuglink */
    strlcpy(current_words, mnemonic_by_screen[current_page],
            MNEMONIC_BY_SCREEN_BUF);

    if (page_count > 1) {
      snprintf(title, MEDIUM_STR_BUF, _("%s %" PRIu32 "/%" PRIu32 ""),
               title_base, current_page + 1, page_count);
    }

    /* Keep the legacy one-request-per-group host protocol while paging the
     * narrower physical OLED layout locally inside that request. */
    if (!confirm_constant_power_paged(type, title,
                                      formatted_mnemonic[current_page])) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Reset cancelled"));
      goto done;
    }
  }

  ok = true;

done:
  memzero(mnemonic_scratch_tokened, sizeof(mnemonic_scratch_tokened));
  memzero(mnemonic_by_screen, sizeof(mnemonic_by_screen));
  memzero(mnemonic_scratch_formatted, sizeof(mnemonic_scratch_formatted));
  memzero(mnemonic_scratch_display, sizeof(mnemonic_scratch_display));
  memzero(mnemonic_scratch_word, sizeof(mnemonic_scratch_word));
  return ok;
}

void reset_entropy(const uint8_t* ext_entropy, uint32_t len) {
  if (!setup_require(SETUP_RESET, _("Not in Reset mode"))) {
    return;
  }

  SHA256_CTX ctx;
  memzero(&ctx, sizeof(ctx));
  /* In either dice mode int_entropy is ALREADY the whole derivation, set in
   * reset_init(), and is used verbatim. The host's EntropyAck is still
   * consumed, so the wire flow and every host stay unchanged, but its bytes
   * are dropped: folding them in would put a value the user does not hold
   * back into the derivation and destroy the offline check that is the
   * entire point of opting in. Not re-hashed either, so the published
   * derivations are exactly what the verifier computes. */
  if (dice_mode == DICE_MODE_NONE) {
    sha256_Init(&ctx);
    sha256_Update(&ctx, int_entropy, 32);
    sha256_Update(&ctx, ext_entropy, len);
    sha256_Final(&ctx, int_entropy);
  }

  const char* temp_mnemonic = mnemonic_from_data(int_entropy, strength / 8);

  memzero(int_entropy, sizeof(int_entropy));

  if (setup.no_backup) {
    /* Consent for this path is the two WARNING holds taken during the same
     * ceremony, in reset_init(). */
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
      /* storage_reset() used to run here. Nothing was written, so there is
       * nothing to reset -- and a host-reachable wipe is not a rollback. */
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
  memzero(mnemonic_scratch_tokened, sizeof(mnemonic_scratch_tokened));
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

/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
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

#ifndef KEEPKEY_FIRMWARE_DICE_INPUT_H
#define KEEPKEY_FIRMWARE_DICE_INPUT_H

#include <stdbool.h>
#include <stdint.h>

/* d6 carries log2(6) = 2.585 bits per roll; targets follow the Coldcard
 * convention of 50 rolls per 128-bit seed and 99 per 256-bit. */
#define DICE_MAX_ROLLS 99

/// How a dice ceremony derives the seed. The host selects the mode in
/// ResetDevice (dice_entropy alone = MIXED, with dice_only = ONLY) and the
/// device shows a consent screen naming it before anything happens. Both
/// opt-in modes are verifiable offline: nothing enters the derivation that
/// the user does not hold, and the host's EntropyAck bytes are consumed and
/// dropped.
typedef enum {
  DICE_MODE_NONE = 0, /* no dice: the legacy device+host derivation */
  DICE_MODE_MIXED,    /* device draw (shown as 24 words) + rolls */
  DICE_MODE_ONLY,     /* rolls alone; the device draw is discarded */
} DiceMode;

/// Number of rolls required for a given seed strength (128/192/256).
uint32_t dice_rolls_for_strength(uint32_t strength_bits);

/// Collect `target` dice rolls on the device with the single button:
/// short press advances the 1-6/UNDO selector, holding the button commits
/// the selection. Announces itself with ButtonRequest_DiceRoll and accepts
/// input only after the host's ButtonAck. Under DEBUG_LINK, characters
/// '1'-'6' and 'u' (undo) arriving in DebugLinkDecision.input are treated
/// as committed selections.
///
/// Fills `rolls` with `target` ASCII digits '1'-'6' (no terminator is
/// appended past target; the caller owns zeroization). Returns false if the
/// host cancelled (Cancel/Initialize).
bool dice_input_collect(char *rolls, uint32_t target);

/// Coldcard's rule: any face landing on more than 30% of the rolls is not a
/// fair die (or not a real one). Also true for any non-'1'..'6' byte.
bool dice_rolls_look_biased(const char *rolls, uint32_t count);

/// ONLY mode: out = SHA256(rolls). Byte-identical to Coldcard's
/// Dice-Rolls-Only derivation, so its published verifier applies unchanged.
void dice_derive_only(const char *rolls, uint32_t count, uint8_t out[32]);

/// MIXED mode, domain-separated after Coldcard's mixed derivation:
///   user = SHA256("KK\x01D" || rolls)
///   out  = SHA256(SHA256("KK\x01SM" || device[32] || user))
/// \a device and \a out may alias.
void dice_derive_mixed(const uint8_t device[32], const char *rolls,
                       uint32_t count, uint8_t out[32]);

#endif

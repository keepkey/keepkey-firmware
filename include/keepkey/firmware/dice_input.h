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

/// entropy = SHA256(entropy[32] || rolls[count]); the caller displays or
/// commits only the post-mix value.
void dice_mix(uint8_t entropy[32], const char *rolls, uint32_t count);

#endif

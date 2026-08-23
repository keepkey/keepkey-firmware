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

#ifndef RNG_H
#define RNG_H

#include <stdint.h>
#include <stdlib.h>

/// Reset the hardware random number generator
#include <stdbool.h>

void reset_rng(void);

/// Boot-lifetime record that the RNG reported a seed or clock error.
///
/// RNG_SR_SEIS latches in hardware only until it is cleared, and random32()
/// clears it whenever the underlying condition has gone -- so a self-test
/// reading RNG_SR alone cannot see a transient fault that random32() already
/// recovered from. This mirror is set at the moment the hardware latch is
/// cleared and is never cleared itself: recovery is a power cycle.
bool rng_seed_error_latched(void);

void random_permute_char(char* str, size_t len);
void random_permute_u16(uint16_t* buf, size_t count);

#endif

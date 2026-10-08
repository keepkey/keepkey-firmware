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

#ifndef SIGNATURES_H
#define SIGNATURES_H

/// Checks firmware signatures
///
///  \returns SIG_OK if signatures are correct
///  \returns KEY_EXPIRED if an expired signature was detected
///  \returns SIG_FAIL for unrecognized signature
int signatures_ok(void);

#include <stdint.h>

/// Verifies three secp256k1 signatures over digest.
///
///  \returns SIG_OK only if all three verify, else SIG_FAIL
int signatures_verify3(const uint8_t* const keys[3],
                       const uint8_t* const sigs[3], const uint8_t digest[32]);

#endif

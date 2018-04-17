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

/* === Defines ============================================================= */

#define PUBKEYS 5
#define PUBKEY_LENGTH 65
#define SIGNATURES 3

#define SIG_OK      0x5A3CA5C3
#define SIG_FAIL    0x00000000

/* === Functions =========================================================== */

int signatures_ok(void);

#endif

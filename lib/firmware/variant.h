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

#ifndef LIB_FIRMWARE_VARIANT_H
#define LIB_FIRMWARE_VARIANT_H

#include <stddef.h>
#include <inttypes.h>
#include <stdbool.h>

const char *variant_getName(void);

/// Perform a soft reset
void variant_mfr_softReset(void) __attribute__((weak));

/// Duration of inactivity before the screensaver should be triggered.
uint32_t variant_getScreensaverTimeout(void);

#endif

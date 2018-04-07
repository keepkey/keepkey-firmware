/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2018 Jon Hodler <jon@keepkey.com>
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

#ifndef INCLUDE_KEEPKEY_BOARD_VARIANT_H
#define INCLUDE_KEEPKEY_BOARD_VARIANT_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

/// \brief Writes a buffer to flash.
///
/// \param address[in]   Where to write the data.
/// \param data[in]      The data to write.
/// \param data_len[in]  How much data to write.
/// \param erase[in]     Whether to clear the sector first.
bool variant_mfr_flashWrite(uint8_t *address, uint8_t *data, size_t data_len,
                             bool erase) __attribute__((weak));

/// \brief Hashes the data stored in the requested areas of flash.
///
/// \param address[in]       The address to start the hash at.
/// \param address_len[in]   The length of data to hash.
/// \param challenge[in]     The challenge to hash with.
/// \param challenge_len[in] The length of the challenge buffer in bytes.
/// \param hash[out]         The contents of the hash.
/// \param hash_len[in]      The number of bytes allowed to be written into hash.
///
/// \returns false iff there was a problem calculating the hash (e.g. permissions, etc)
bool variant_mfr_flashHash(uint8_t *address, size_t address_len,
                                   uint8_t *challenge, size_t challenge_len,
                                   uint8_t *hash, size_t hash_len) __attribute__((weak));

/// Dump chunks of flash. Behaves like memcpy.
void variant_mfr_flashDump(uint8_t *dst, uint8_t *src, size_t len) __attribute__((weak));

/// Get the sector number for an address.
uint8_t variant_mfr_sectorFromAddress(uint8_t *address) __attribute__((weak));

/// Get the starting address of a sector.
void *variant_mfr_sectorStart(uint8_t sector) __attribute__((weak));

/// Get the length of a sector.
uint32_t variant_mfr_sectorLength(uint8_t sector) __attribute__((weak));

#endif

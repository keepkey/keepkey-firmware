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

#include "keepkey/firmware/storage.h"

#ifndef EMULATOR
#include <libopencm3/stm32/crc.h>
#include <libopencm3/stm32/desig.h>
#include <libopencm3/stm32/flash.h>
#endif

#include "keepkey/board/supervise.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/util.h"
#include "keepkey/rand/rng.h"

#include <string.h>
#include <stdint.h>
#include <assert.h>

static Allocation storage_location = FLASH_INVALID;

static bool storage_isActiveSector(const void* flash) {
  return memcmp(((const Metadata *)flash)->magic, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN) == 0;
}

static void storage_resetUuid(Metadata *meta) {
#ifdef EMULATOR
  random_buffer(meta->uuid, sizeof(meta->uuid));
#else
  _Static_assert(sizeof(meta->uuid) == 3 * sizeof(uint32_t), "uuid not large enough");
  desig_get_unique_id((uint32_t *)meta->uuid);
#endif
  data2hex(meta->uuid, sizeof(meta->uuid), meta->uuid_str);
}

bool storage_read(uint8_t* buf, size_t len) {
  if (len > FLASH_STORAGE_LEN - FLASH_STORAGE_META_LEN) return false;

  // Find storage sector with valid data and set storage_location variable.
  if (!find_active_storage(&storage_location)) {
    // Otherwise initialize it to the default sector.
    storage_location = STORAGE_SECT_DEFAULT;
  }
  const uint8_t* flash = flash_write_helper(storage_location, NULL, 0);

  memset(buf, 0, len);

  // If the storage partition is not already active
  if (!storage_isActiveSector(flash)) {
    // ... activate it by populating new Metadata section,
    // and writing it to flash.
    return storage_write(NULL, 0);
  }

  memcpy(buf, flash + FLASH_STORAGE_META_LEN, len);
  return true;
}

void storage_wipe(void) {
  flash_erase_word(FLASH_STORAGE1);
  flash_erase_word(FLASH_STORAGE2);
  flash_erase_word(FLASH_STORAGE3);
}

bool storage_commit(const uint8_t* buf, size_t len) {
  if (len > FLASH_STORAGE_LEN - STORAGE_MAGIC_LEN) return false;
  if (len % sizeof(uint32_t) != 0) return false; // buffer size must be a whole number of words

  uint8_t metaBuf[FLASH_STORAGE_META_LEN] = { 0 };
  _Static_assert(sizeof(metaBuf) >= 16 + STORAGE_UUID_STR_LEN, "metaBuf size is too short");
  _Static_assert(sizeof(metaBuf) % sizeof(uint32_t) == 0, "metaBuf size must be a whole number of words");

  {
    Metadata* meta = (Metadata*)metaBuf;
    memcpy(meta->magic, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN);
    storage_resetUuid(meta);
  }

  uint32_t retries = 0;
  for (retries = 0; retries < STORAGE_RETRIES; retries++) {
    /* Capture CRC for verification at restore */
    crc_reset();
    // Salt the CRC so that retries have a chance of not hitting 0
    crc_calculate_block(&retries, 1);
    crc_calculate_block((uint32_t*)&metaBuf, sizeof(metaBuf) / sizeof(uint32_t));
    uint32_t ram_crc32 = crc_calculate_block((uint32_t*)buf, len / sizeof(uint32_t));
    if (ram_crc32 == 0) continue; // Retry

    /* Make sure storage sector is valid before proceeding */
    if (storage_location < FLASH_STORAGE1 || storage_location > FLASH_STORAGE3) {
      /* Let it exhaust the retries and error out */
      continue;
    }

    flash_erase_word(storage_location);
    storage_location = next_storage(storage_location); // Wear leveling shift
    flash_erase_word(storage_location);

    /* Write storage data first before writing storage metadata */
    if (!flash_write_word(storage_location, sizeof(metaBuf), len, buf)) {
      flash_erase_word(storage_location);
      continue;  // Retry
    }

    if (!flash_write_word(storage_location, 0, sizeof(metaBuf), metaBuf)) {
      flash_erase_word(storage_location);
      continue;  // Retry
    }

    /* Flash write completed successfully.  Verify CRC */
    const uint8_t* flash = flash_write_helper(storage_location, NULL, 0);
    crc_reset();
    crc_calculate_block(&retries, 1);
    uint32_t flash_crc32 = crc_calculate_block((uint32_t*)flash, (sizeof(metaBuf) + len) / sizeof(uint32_t));

    if (flash_crc32 != ram_crc32) {
      flash_erase_word(storage_location);
      continue;  // Retry
    }

    /* Commit successful */
    storage_protect_off();
    return true;
  }

  storage_wipe();
  return false;
}

/*
 * This file is part of the KEEPKEY project
 *
 * Copyright (C) 2018 KEEPKEY
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

#include "keepkey/board/bl_mpu.h"

#ifndef EMULATOR
#include <libopencm3/stm32/flash.h>
#include <libopencm3/stm32/timer.h>
#ifdef DEV_DEBUG
#include <libopencm3/stm32/f4/nvic.h>
#else
#include <libopencm3/stm32/f2/nvic.h>
#endif
#include <libopencm3/stm32/rcc.h>
#endif

#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/layout.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>

/// \brief bootloader-only version of flash erase in word (32bit) size
///
/// Must be run from bootloader with privileged access or it may cause a memory
/// protect failure.
void bl_flash_erase_word(Allocation group) {
#ifndef EMULATOR
  const FlashSector* s = flash_sector_map;
  while (s->use != FLASH_INVALID) {
    if (s->use == group) {
      bl_flash_erase_sector(s->sector);
    }
    ++s;
  }
#endif
}

/// bootloader-only: flash-erase that erases a given sector in 32bit chunks
void bl_flash_erase_sector(int sector) {
#ifndef EMULATOR
  const FlashSector* s = flash_sector_map;
  while (s->use != FLASH_INVALID) {
    if (s->sector == sector) {
      // unlock the flash
      flash_clear_status_flags();
      flash_unlock();

      // erase the sector
      flash_erase_sector(s->sector, FLASH_CR_PROGRAM_X32);

      // lock the flash
      /* Wait for any write operation to complete. */
      flash_wait_for_last_operation();
      /* Disable writes to flash. */
      FLASH_CR &= ~FLASH_CR_PG;
      /* lock flash register */
      FLASH_CR |= FLASH_CR_LOCK;
      /* return flash status register */
      break;
    }
    ++s;
  }
#endif
}

/// Initialize Board
void bl_board_init(void) {
#ifndef EMULATOR
  // Enable Clock Security System
  rcc_css_enable();
#endif
}

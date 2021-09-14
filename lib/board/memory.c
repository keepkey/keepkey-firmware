/*
 * This file is part of the KEEPKEY project.
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

#ifndef EMULATOR
#include <libopencm3/stm32/flash.h>
#include <libopencm3/cm3/mpu.h>
#include <libopencm3/cm3/nvic.h>
#include <libopencm3/cm3/scb.h>
#include "keepkey/board/mpudefs.h"
#else
#include <stdio.h>
#endif

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/keepkey_flash.h"

#include <string.h>
#include <assert.h>
#include <stdint.h>

#ifdef EMULATOR
uint8_t *emulator_flash_base = NULL;
#endif

void mpu_config(void) {
  // CAUTION: It is possible to disable access to critical resources even in
  // privileged mode. This can potentially birck device

#ifndef EMULATOR
  MPU_CTRL = 0;

  // Note: later entries overwrite previous ones
  // Flash (0x08000000 - 0x080FFFFF, 1 MiB, read-only)
  MPU_RBAR = FLASH_BASE | MPU_RBAR_VALID | (0 << MPU_RBAR_REGION_LSB);
  MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_FLASH | MPU_RASR_SIZE_1MB |
             MPU_RASR_ATTR_AP_PRW_URO;

  // SRAM (0x20000000 - 0x2001FFFF, read-write, execute never)
  MPU_RBAR = SRAM_BASE | MPU_RBAR_VALID | (1 << MPU_RBAR_REGION_LSB);
  MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_SRAM | MPU_RASR_SIZE_128KB |
             MPU_RASR_ATTR_AP_PRW_URW | MPU_RASR_ATTR_XN;

  // SRAM (0x2001F800 - 0x2001FFFF, bootloader protected ram, priv read-write
  // only, execute never, disable high subregion)
  MPU_RBAR = BLPROTECT_BASE | MPU_RBAR_VALID | (2 << MPU_RBAR_REGION_LSB);
  MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_SRAM | MPU_RASR_DIS_SUB_8 |
             MPU_RASR_SIZE_2KB | MPU_RASR_ATTR_AP_PRW_UNO | MPU_RASR_ATTR_XN;

  // Peripherals are not accessible by default, allow unpriv access (0x40020000
  // - 0x40023FFF, read-write, execute never)
  MPU_RBAR = 0x40020000 | MPU_RBAR_VALID | (3 << MPU_RBAR_REGION_LSB);
  MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_PERIPH | MPU_RASR_SIZE_16KB |
             MPU_RASR_ATTR_AP_PRW_URW | MPU_RASR_ATTR_XN;

  // by default, the flash controller regs are accessible in unpriv mode, apply
  // protection (0x40023C00 - 0x40023FFF, privileged read-write, unpriv no,
  // execute never)
  MPU_RBAR = 0x40023c00 | MPU_RBAR_VALID | (4 << MPU_RBAR_REGION_LSB);
  MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_PERIPH | MPU_RASR_SIZE_1KB |
             MPU_RASR_ATTR_AP_PRW_UNO | MPU_RASR_ATTR_XN;

#ifdef USART_DEBUG_ON
  // USART3 is open to unprivileged access for usart debug versions only
  // (0x40004800 - 0x40004BFF)
  MPU_RBAR = 0x40004800 | MPU_RBAR_VALID | (5 << MPU_RBAR_REGION_LSB);
  MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_PERIPH | MPU_RASR_SIZE_1KB |
             MPU_RASR_ATTR_AP_PRW_URW | MPU_RASR_ATTR_XN;
#else
  // If using release firmware, use this region to protect the sysconfig
  // registers (0x40013800 - 0x40013BFF, read-only, execute never)
  MPU_RBAR = 0x40013800 | MPU_RBAR_VALID | (5 << MPU_RBAR_REGION_LSB);
  MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_PERIPH | MPU_RASR_SIZE_1KB |
             MPU_RASR_ATTR_AP_PRO_UNO | MPU_RASR_ATTR_XN;
#endif

  // Allow access to the block from the USB FS periph up through the RNG to
  // capture these two periphs in one region (0x50000000 - 0x50080000)
  MPU_RBAR = 0x50060800 | MPU_RBAR_VALID | (6 << MPU_RBAR_REGION_LSB);
  MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_PERIPH | MPU_RASR_SIZE_512KB |
             MPU_RASR_ATTR_AP_PRW_URW | MPU_RASR_ATTR_XN;

  // OTP and unique ids is open to unprivileged access
  // (0x1FFF7800 - 0x1FFF7C00)
  MPU_RBAR = 0x1FFF7800 | MPU_RBAR_VALID | (7 << MPU_RBAR_REGION_LSB);
  MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_PERIPH | MPU_RASR_SIZE_1KB |
             MPU_RASR_ATTR_AP_PRW_URW | MPU_RASR_ATTR_XN;

  // Enable MPU and use the default system memory privileges as the background
  // execution of the system memory map.
  MPU_CTRL = MPU_CTRL_ENABLE | MPU_CTRL_PRIVDEFENA;

  // Enable memory fault handler
  SCB_SHCSR |= SCB_SHCSR_MEMFAULTENA;

  __asm__ volatile("dsb");
  __asm__ volatile("isb");
#endif  // EMULATOR
}

/*
 * find_active_storage() - Find a sector with valid data
 *
 * INPUT -
 *       - storage_location: pointer to save config data
 * OUTPUT -
 *      status
 *
 */
bool find_active_storage(Allocation *storage_location) {
  bool ret_stat = false;
  Allocation storage_location_use;
  const uint8_t* storage_location_start;

  /* Find 1st storage sector with valid data */
  for (storage_location_use = FLASH_STORAGE1;
       storage_location_use <= FLASH_STORAGE3; storage_location_use++) {
    storage_location_start = flash_write_helper(storage_location_use, NULL, 0);

    if (memcmp(storage_location_start, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN) == 0) {
      /* Found valid data.  Load data and exit */
      *storage_location = storage_location_use;
      ret_stat = true;
      break;
    }
  }

  return ret_stat;
}

Allocation next_storage(Allocation active) {
  switch (active) {
    case FLASH_STORAGE1:
      return FLASH_STORAGE2;
    case FLASH_STORAGE2:
      return FLASH_STORAGE3;
    case FLASH_STORAGE3:
      return FLASH_STORAGE1;
    default:
      assert(false && "Unsupported storage sector provided");
      return FLASH_STORAGE1;
  }
}


/// Write the marker that allows the firmware to boot.
/// \returns true iff successful
bool storage_protect_off(void) {
  Allocation active;
  if (!find_active_storage(&active)) return false;

  Allocation marker_sector = next_storage(active);
  flash_erase_word(marker_sector);
  bool ret = flash_write(marker_sector, 0, sizeof(STORAGE_PROTECT_OFF_MAGIC),
                         (const uint8_t *)STORAGE_PROTECT_OFF_MAGIC);
  return ret;
}

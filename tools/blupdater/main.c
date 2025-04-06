/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2018 KeepKey LLC
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

/**
 * \file Bootloader Update Tool
 *
 * On a high-level, this tool's job is to update a device's bootloader. In
 * order to do so safely and avoid bricking devices, we take several
 * precautions:
 *
 *    1) This tool refuses to update bootloaders it does not recognize. This
 *       prevents bootloader downgrade attacks, should we need to update the
 *       bootloader again in the future.
 *    2) Data to be written is checked before and after for hash correctness.
 *    3) Writes are re-attempted several times in case of failure.
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifndef EMULATOR
#include <libopencm3/cm3/cortex.h>
#include <libopencm3/stm32/flash.h>

#include <libopencm3/cm3/mpu.h>
#include <libopencm3/cm3/scb.h>
#include <libopencm3/cm3/vector.h>
#include "keepkey/board/mpudefs.h"
#endif

#include "keepkey/board/check_bootloader.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/draw.h"
#include "keepkey/board/layout.h"
#include "hwcrypto/crypto/sha2.h"

#include "keepkey/firmware/app_layout.h"

#include <memory.h>
#include <string.h>

#define NUM_RETRIES 8
#define CHUNK_SIZE 0x100

#define BL_VERSION                                           \
  VERSION_STR(BOOTLOADER_MAJOR_VERSION)                      \
  "." VERSION_STR(BOOTLOADER_MINOR_VERSION) "." VERSION_STR( \
      BOOTLOADER_PATCH_VERSION)

static uint8_t payload_hash[SHA256_DIGEST_LENGTH];
extern const uint8_t _binary_payload_bin_start[];
extern const uint8_t _binary_payload_bin_end[];
static int _binary_payload_bin_size;

void mmhisr(void);
void mpu_blup(void);

/* These variables will be used by host application to read the version info */
static const char *const application_version
    __attribute__((used, section("version"))) = "VERSION" BL_VERSION;

/// \returns true iff there was a problem while writing.
static bool write_bootloader(void) {
  static uint8_t hash[SHA256_DIGEST_LENGTH];
  memset(hash, 0, sizeof(hash));
  sha256_Raw((const uint8_t *)_binary_payload_bin_start,
             _binary_payload_bin_size, hash);

  for (int i = 0; i < NUM_RETRIES; ++i) {
    // Enable writing to the read-only sectors
    memory_unlock();
    flash_unlock();

    // erase the bootloader sectors, do not use flash_erase_word()
    layoutProgress("Updating Bootloader. DO NOT UNPLUG", 0);
    flash_erase_sector(5, FLASH_CR_PROGRAM_X32);
    flash_wait_for_last_operation();
    layoutProgress("Updating Bootloader. DO NOT UNPLUG", 100);
    flash_erase_sector(6, FLASH_CR_PROGRAM_X32);
    flash_wait_for_last_operation();

    // Write into the sector.
    for (int chunkstart = 0; chunkstart < _binary_payload_bin_size;
         chunkstart += CHUNK_SIZE) {
      layoutProgress("Updating Bootloader. DO NOT UNPLUG",
                     200 + chunkstart * 800 / _binary_payload_bin_size);

      size_t chunksize;
      if (_binary_payload_bin_size > chunkstart + CHUNK_SIZE) {
        chunksize = CHUNK_SIZE;
      } else {
        chunksize = _binary_payload_bin_size - chunkstart;
      }

      flash_program((uint32_t)(FLASH_BOOT_START + chunkstart),
                    &_binary_payload_bin_start[chunkstart], chunksize);
      flash_wait_for_last_operation();
    }

    // Disallow writing to flash.
    flash_lock();

    // Ignore any reported errors, we only care about the end result.
    flash_clear_status_flags();

    memset(hash, 0, sizeof(hash));
    sha256_Raw((const uint8_t *)FLASH_BOOT_START, _binary_payload_bin_size,
               hash);

    if (!memcmp(hash, payload_hash, sizeof(hash))) {
      // Success
      return false;
    }
  }

  // Failure
  return true;
}

/// \returns true iff the bootloader is something we don't recognize
static bool unknown_bootloader(void) {
  switch (get_bootloaderKind()) {
    case BLK_UNKNOWN:
      return true;

    case BLK_v1_0_0:
    case BLK_v1_0_1:
    case BLK_v1_0_2:
    case BLK_v1_0_3:
    case BLK_v1_0_3_sig:
    case BLK_v1_0_3_elf:
    case BLK_v1_0_4:
    case BLK_v1_1_0:
    case BLK_v2_0_0:
    case BLK_v2_1_0:
    case BLK_v2_1_1:
    case BLK_v2_1_2:
    case BLK_v2_1_3:
    case BLK_v2_1_4:
      return false;
  }

  __builtin_unreachable();
}

/// \brief Success: everything went smoothly as expected, and the device has a
///        new bootloader installed.
static void success(void) {
  layout_standard_notification("Bootloader Update Complete",
                               "Your device will now restart",
                               NOTIFICATION_CONFIRMED);
  display_refresh();
  delay_ms(3000);
  board_reset(RESET_PARAM_REQUEST_UPDATE);
}

/// \brief Hard Failure: something went wrong during the write, and it's
///        exceedingly unlikely that we'll be able to recover.
static void failure(void) {
  layout_warning_static("Update failed. Please contact support.");
  display_refresh();
}

/// \brief Byte-wise substring search, using the Two-Way algorithm.
///
/// Locates the first occurrence in the memory region pointed to
/// by <[s1]> with length <[l1]> of the sequence of bytes pointed
/// to by <[s2]> of length <[l2]>.  If you already know the
/// lengths of your haystack and needle, <<memmem>> can be much
/// faster than <<strstr>>.
///
/// \returns a pointer to the located segment, or a null pointer if
/// <[s2]> is not found. If <[l2]> is 0, <[s1]> is returned.
///
/// Copyright (C) 2008 Eric Blake
/// Permission to use, copy, modify, and distribute this software
/// is freely granted, provided that this notice is preserved.
/// https://github.com/eblot/newlib/blob/2a63fa0fd26ffb6603f69d9e369e944fe449c246/newlib/libc/string/memmem.c
static void *memmem(const void *haystack_start, size_t haystack_len,
                    const void *needle_start, size_t needle_len) {
  /* Abstract memory is considered to be an array of 'unsigned char' values,
     not an array of 'char' values.  See ISO C 99 section 6.2.6.1.  */
  const unsigned char *haystack = (const unsigned char *)haystack_start;
  const unsigned char *needle = (const unsigned char *)needle_start;

  if (needle_len == 0) {
    /* The first occurrence of the empty string is deemed to occur at
       the beginning of the string.  */
    return (void *)haystack;
  }

  /* Less code size, but quadratic performance in the worst case.  */
  while (needle_len <= haystack_len) {
    if (!memcmp(haystack, needle, needle_len)) return (void *)haystack;
    haystack++;
    haystack_len--;
  }
  return NULL;
}

int main(void) {
  _buttonusr_isr = (void *)&buttonisr_usr;
  _timerusr_isr = (void *)&timerisr_usr;
  _mmhusr_isr = (void *)&mmhisr;

  mpu_blup();

  // Legacy bootloader code will have interrupts disabled at this point. To
  // maintain compatibility, the timer and button interrupts need to be enabled
  // and then global interrupts enabled. This is a nop in the modern scheme
  cm_enable_interrupts();

  kk_board_init();

  memset(payload_hash, 0, sizeof(payload_hash));
  _binary_payload_bin_size =
      _binary_payload_bin_end - _binary_payload_bin_start;
  sha256_Raw((const uint8_t *)_binary_payload_bin_start,
             _binary_payload_bin_size, payload_hash);

#ifndef DEBUG_ON  // for testing, update every time even if it's the same bl
  // Check if we've already updated
  static uint8_t hash[SHA256_DIGEST_LENGTH];
  memset(hash, 0, sizeof(hash));
  sha256_Raw((const uint8_t *)FLASH_BOOT_START, _binary_payload_bin_size, hash);

  if (!memcmp(hash, payload_hash, sizeof(hash))) {
    success();
    return 0;
  }
#endif

  // Check that we're familiar with this bootloader, and refuse to update
  // anything we don't recognize. This prevents use of this tool in a
  // hypothetical bootloader downgrade attack.
  if (unknown_bootloader()) {
#ifndef DEBUG_ON
    layout_warning_static("Unknown bootloader. Please contact support.");
    display_refresh();
    return 0;
#endif
  }

  // Make sure that we cannot mismatch BL_VERSION with the version string
  // that's actually in the bootloader we're about to write to the device.
  // This implies that the version of blupdater, and the bootloader it writes
  // must always be the same.
  if (!memmem((const char *)_binary_payload_bin_start, _binary_payload_bin_size,
              application_version, strlen(application_version))) {
#ifndef DEBUG_ON
    layout_warning_static("version mismatch");
    display_refresh();
    return 0;
#endif
  }

  // Shove the model # into OTP if it wasn't already there.
  (void)flash_programModel();

  // Add Storage Protection magic, since older firmwares have never written it.
  Allocation active_storage;
  if (find_active_storage(&active_storage)) {
    storage_protect_off();
  }

  if (write_bootloader()) {
    failure();
    return 0;
  }

  success();
  return 0;
}

/*
   The blupdater scheme is designed to run as a privileged mode fw version. The
   blupdater must be signed just as any other kk defined firmware, however the
   bootloader needs to distinguish this firmware from normal operating firmware.
   This is the ethernet DMA isr (61), extremely unlikely to ever be required in
   a kk device. This unique vector can be read by the bootloader that will then
   subsequently allow continuation in a mode appropriate for the blupdater, that
   is, privileged mode execution using its own vector table.
   */

void eth_isr(void) {
  while (1)
    ;
}

void mpu_blup(void) {
#ifndef EMULATOR
  // basic memory protection for the blupdater. More regions can be added if
  // needed. CAUTION: It is possible to disable access to critical resources
  // even in privileged mode. This can potentially brick devices

  // Disable MPU
  MPU_CTRL = 0;

  // Note: later entries overwrite previous ones
  // Flash (0x08000000 - 0x080FFFFF, 1 MiB, read-only)
  MPU_RBAR = FLASH_BASE | MPU_RBAR_VALID | (0 << MPU_RBAR_REGION_LSB);
  MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_FLASH | MPU_RASR_SIZE_1MB |
             MPU_RASR_ATTR_AP_PRW_URO;
  // Sector 0 (bootstrap) is protected
  // (0x08000000 - 0x08003FFF, 16 KiB)
  MPU_RBAR = (FLASH_BASE) | MPU_RBAR_VALID | (1 << MPU_RBAR_REGION_LSB);
  MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_FLASH | MPU_RASR_SIZE_16KB |
             MPU_RASR_ATTR_AP_PRO_UNO;

  // Enable MPU and allow privileged execution of the system memory map. If
  // unprivileged access of the system memory map is desired, do not set this
  // bit and add mpu coverage of the region.
  MPU_CTRL = MPU_CTRL_ENABLE | MPU_CTRL_PRIVDEFENA;

  // Enable memory fault handler
  SCB_SHCSR |= SCB_SHCSR_MEMFAULTENA;

  __asm__ volatile("dsb");
  __asm__ volatile("isb");
#endif  // EMULATOR
}

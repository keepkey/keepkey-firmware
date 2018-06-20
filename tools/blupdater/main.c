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

#include <libopencm3/cm3/cortex.h>
#include <libopencm3/stm32/flash.h>

#include "keepkey/board/check_bootloader.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/draw.h"
#include "keepkey/board/layout.h"
#include "keepkey/crypto/sha2.h"

#include "keepkey/firmware/app_layout.h"

#include <memory.h>
#include <string.h>

#define NUM_RETRIES 8

#ifdef DEBUG_ON
static uint8_t bl_hash[SHA256_DIGEST_LENGTH];
#  define BL_HASH bl_hash
#  define BL_VERSION "DEBUG"
#  include "bin/bootloader.debug.h"
#else
#  include "bin/bootloader.release.h"
#endif

/* These variables will be used by host application to read the version info */
static const char *const application_version
__attribute__((used, section("version"))) = "VERSION" BL_VERSION;

/// \returns true iff there was a problem while writing.
static bool write_bootloader(void)
{
    static uint8_t hash[SHA256_DIGEST_LENGTH];
    memset(hash, 0, sizeof(hash));
    sha256_Raw((const uint8_t*)bootloader, sizeof(bootloader), hash);

    if (memcmp(hash, BL_HASH, sizeof(hash)))
        return true;

    for (int i = 0; i < NUM_RETRIES; ++i) {
        // Enable writing to the read-only sectors
        memory_unlock();
        flash_unlock();

        flash_erase_word(FLASH_BOOTLOADER);

        // Write into the sector.
        flash_program((uint32_t)FLASH_BOOT_START, bootloader, sizeof(bootloader));

        // Disallow writing to flash.
        flash_lock();

        // Ignore any reported errors, we only care about the end result.
        flash_clear_status_flags();

        memset(hash, 0, sizeof(hash));
        sha256_Raw((const uint8_t*)FLASH_BOOT_START, sizeof(bootloader), hash);

        if (!memcmp(hash, BL_HASH, sizeof(hash))) {
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
        return false;
    }

    __builtin_unreachable();
}

/// \brief Success: everything went smoothly as expected, and the device has a
///        new bootloader installed.
static void success(void) {
    layout_warning_static("Bootloader successfully updated to v" BL_VERSION);
    display_refresh();
    delay_ms(5000);

    layout_standard_notification("Bootloader Update Complete",
                                 "Please disconnect and reconnect while holding the button.",
                                 NOTIFICATION_UNPLUG);
    display_refresh();
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
   const unsigned char *haystack = (const unsigned char *) haystack_start;
   const unsigned char *needle = (const unsigned char *) needle_start;

   if (needle_len == 0) {
       /* The first occurrence of the empty string is deemed to occur at
          the beginning of the string.  */
       return (void*)haystack;
   }

   /* Less code size, but quadratic performance in the worst case.  */
   while (needle_len <= haystack_len) {
       if (!memcmp(haystack, needle, needle_len))
           return (void*)haystack;
       haystack++;
       haystack_len--;
   }
   return NULL;
}

int main(void)
{
    board_init();
    cm_enable_interrupts();

#ifdef DEBUG_ON
    memset(bl_hash, 0, sizeof(bl_hash));
    sha256_Raw((const uint8_t*)bootloader, sizeof(bootloader), bl_hash);
#endif

    // Check if we've already updated
    static uint8_t hash[SHA256_DIGEST_LENGTH];
    memset(hash, 0, sizeof(hash));
    sha256_Raw((const uint8_t*)FLASH_BOOT_START, sizeof(bootloader), hash);
    if (!memcmp(hash, BL_HASH, sizeof(hash))) {
        success();
        return 0;
    }

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
    if (!memmem((const char*)bootloader, sizeof(bootloader),
                application_version, strlen(application_version))) {
#ifndef DEBUG_ON
        layout_warning_static("version mismatch");
        display_refresh();
        return 0;
#endif
    }

    layout_simple_message("Updating bootloader to v" BL_VERSION);
    display_refresh();

    // Shove the model # into OTP if it wasn't already there.
    (void)flash_programModel();

    if (write_bootloader()) {
        failure();
        return 0;
    }

    success();
    return 0;
}

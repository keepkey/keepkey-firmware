/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2018 keepkeyjon <jon@keepkey.com>
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

#include "keepkey/firmware/hotpatch_bootloader.h"

#include "keepkey/board/check_bootloader.h"

#ifndef EMULATOR
#  include <libopencm3/stm32/flash.h>
#endif

#include "keepkey/crypto/sha2.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/memory.h"

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

enum BL_Status {
    BL_UNKNOWN       = 0x0,
    BL_HOTPATCHABLE  = 0xa1f35c78,
    BL_PATCH_APPLIED = 0x95c3a027,
};

static enum BL_Status check_bootloader_status(void) {
    static uint8_t bl_hash[SHA256_DIGEST_LENGTH];
    if (32 != memory_bootloader_hash(bl_hash, /*cached=*/ false))
        return BL_UNKNOWN;

    // Hotpatch unnecessary
    // --------------------
    if (0 == memcmp(bl_hash, bl_hash_v1_1_0, 32))
        return BL_PATCH_APPLIED; // bl_hash_v1.1.0, KeepKey + PoweredBy

    // Fixed bootloaders
    // ---------------------
    if (0 == memcmp(bl_hash, bl_hash_v1_0_0_hotpatched, 32))
        return BL_PATCH_APPLIED; // bl_hash_v1.0.0, fixed

    if (0 == memcmp(bl_hash, bl_hash_v1_0_1_hotpatched, 32))
        return BL_PATCH_APPLIED; // bl_hash_v1.0.1, fixed

    if (0 == memcmp(bl_hash, bl_hash_v1_0_2_hotpatched, 32))
        return BL_PATCH_APPLIED; // bl_hash_v1.0.2, fixed

    if (0 == memcmp(bl_hash, bl_hash_v1_0_3_hotpatched, 32))
        return BL_PATCH_APPLIED; // bl_hash_v1.0.3, fixed

    if (0 == memcmp(bl_hash, bl_hash_v1_0_3_sig_hotpatched, 32))
        return BL_PATCH_APPLIED; // bl_hash_v1.0.3_signed, fixed

    if (0 == memcmp(bl_hash, bl_hash_v1_0_3_elf_hotpatched, 32))
        return BL_PATCH_APPLIED; // bl_hash_v1.0.3_signed, fixed from version generated from elf

    if (0 == memcmp(bl_hash, bl_hash_v1_0_4_hotpatched, 32))
        return BL_PATCH_APPLIED; // bl_hash_v1.0.4, fixed - SALT whitelabel

    // Unpatched bootloaders
    // ---------------------
    if (0 == memcmp(bl_hash, bl_hash_v1_0_0_unpatched, 32))
        return BL_HOTPATCHABLE; // bl_hash_v1.0.0, unpatched
;
    if (0 == memcmp(bl_hash, bl_hash_v1_0_1_unpatched, 32))
        return BL_HOTPATCHABLE; // bl_hash_v1.0.1, unpatched

    if (0 == memcmp(bl_hash, bl_hash_v1_0_2_unpatched, 32))
        return BL_HOTPATCHABLE; // bl_hash_v1.0.2, unpatched

    if (0 == memcmp(bl_hash, bl_hash_v1_0_3_unpatched, 32))
        return BL_HOTPATCHABLE; // bl_hash_v1.0.3, unpatched

    if (0 == memcmp(bl_hash, bl_hash_v1_0_3_sig_unpatched, 32))
        return BL_HOTPATCHABLE; // bl_hash_v1.0.3_signed, unpatched

    if (0 == memcmp(bl_hash, bl_hash_v1_0_3_elf_unpatched, 32))
        return BL_HOTPATCHABLE; // bl_hash_v1.0.3_signed, version generated from elf

    if (0 == memcmp(bl_hash, bl_hash_v1_0_4_unpatched, 32))
        return BL_HOTPATCHABLE; // bl_hash_v1.0.4, unpatched - SALT whitelabel

    return BL_UNKNOWN;
}

/*
 * Hot-patch old bootloaders to disallow executing unsigned firmwares.
 *
 * \returns true iff this bootloader has been hotpatched
 */
static bool apply_hotpatch(void)
{
#ifndef EMULATOR
    const uintptr_t hotpatch_addr = 0x802026c;

    static const char hotpatch[18] = {
        0x00, 0x00, // movs r0, r0
        0x00, 0x00, // movs r0, r0
        0x00, 0x00, // movs r0, r0
        0x00, 0x00, // movs r0, r0
        0x00, 0x00, // movs r0, r0
        0x00, 0x00, // movs r0, r0
        0x00, 0x00, // movs r0, r0
        0x00, 0x00, // movs r0, r0
    };

    // Enable writing to the read-only sectors
    memory_unlock();
    flash_unlock();

    // Write into the sector.
    flash_program((uint32_t)hotpatch_addr, (uint8_t*)hotpatch, sizeof(hotpatch));

    // Disallow writing to flash.
    flash_lock();

    // Ignore the reported error.
    flash_clear_status_flags();

    // Check for the hotpatch sequence
    return memcmp((void*)hotpatch_addr, hotpatch, sizeof(hotpatch)) == 0;
#else
    return false;
#endif
}

void check_bootloader(void) {
#ifndef EMULATOR
    enum BL_Status status = check_bootloader_status();

#if defined(DEBUG_ON)
    status = BL_PATCH_APPLIED;
#endif

    if (status == BL_HOTPATCHABLE) {
        if (!apply_hotpatch()) {
            layout_warning_static("Hotpatch failed. Contact support.");
            shutdown();
        }
    } else if (status == BL_UNKNOWN) {
        layout_warning_static("Unknown bootloader. Contact support.");
        shutdown();
    } else if (status == BL_PATCH_APPLIED) {
        // do nothing, bootloader is already safe
    } else {
        layout_warning_static("B/L check failed. Reboot Device!");
        shutdown();
    }
#endif
}


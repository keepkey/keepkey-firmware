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

#include <libopencm3/stm32/flash.h>

#include "keepkey/crypto/sha2.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/memory.h"

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

enum BL_Kind {
    BL_UNKNOWN       = 0x0,
    BL_HOTPATCHABLE  = 0xa1f35c78,
    BL_PATCH_APPLIED = 0x95c3a027,
};

static enum BL_Kind check_bootloader_kind(void) {
    static uint8_t bl_hash[SHA256_DIGEST_LENGTH];
    if (32 != memory_bootloader_hash(bl_hash))
        return BL_UNKNOWN;

#if defined(DEBUG_ON)
    return BL_PATCH_APPLIED;
#else
    // Fixed bootloaders
    // ---------------------
    if (0 == memcmp(bl_hash, "\xf1\x3c\xe2\x28\xc0\xbb\x2b\xdb\xc5\x6b\xdc\xb5\xf4\x56\x93\x67\xf8\xe3\x01\x10\x74\xcc\xc6\x33\x31\x34\x8d\xeb\x49\x8f\x2d\x8f", 32))
        return BL_PATCH_APPLIED; // v1.0.0, fixed

    if (0 == memcmp(bl_hash, "\xec\x61\x88\x36\xf8\x64\x23\xdb\xd3\x11\x4c\x37\xd6\xe3\xe4\xff\xdf\xb8\x7d\x9e\x4c\x61\x99\xcf\x3e\x16\x3a\x67\xb2\x74\x98\xa2", 32))
        return BL_PATCH_APPLIED; // v1.0.1, fixed

    if (0 == memcmp(bl_hash, "\xbc\xaf\xb3\x8c\xd0\xfb\xd6\xe2\xbd\xbe\xa8\x9f\xb9\x02\x35\x55\x9f\xdd\xa3\x60\x76\x5b\x74\xe4\xa8\x75\x8b\x4e\xff\x2d\x49\x21", 32))
        return BL_PATCH_APPLIED; // v1.0.2, fixed

    if (0 == memcmp(bl_hash, "\x83\xd1\x4c\xb6\xc7\xc4\x8a\xf2\xa8\x3b\xc3\x26\x35\x3e\xe6\xb9\xab\xdd\x74\xcf\xe4\x7b\xa5\x67\xde\x1c\xb5\x64\xda\x65\xe8\xe9", 32))
        return BL_PATCH_APPLIED; // v1.0.3, fixed

    if (0 == memcmp(bl_hash, "\x91\x7d\x19\x52\x26\x0c\x9b\x89\xf3\xa9\x6b\xea\x07\xee\xa4\x07\x4a\xfd\xcc\x0e\x8c\xdd\x5d\x06\x4e\x36\x86\x8b\xdd\x68\xba\x7d", 32))
        return BL_PATCH_APPLIED; // v1.0.3_signed, fixed

    if (0 == memcmp(bl_hash, "\xdb\x4b\xc3\x89\x33\x5e\x87\x6e\x94\x2a\xe3\xb1\x25\x58\xce\xcd\x20\x2b\x74\x59\x03\xe7\x9b\x34\xdd\x2c\x32\x53\x27\x08\x86\x0e", 32))
        return BL_PATCH_APPLIED; // v1.0.3_signed, fixed from version generated from elf

    if (0 == memcmp(bl_hash, "\xfc\x4e\x5c\x4d\xc2\xe5\x12\x7b\x68\x14\xa3\xf6\x94\x24\xc9\x36\xf1\xdc\x24\x1d\x1d\xaf\x2c\x5a\x2d\x8f\x07\x28\xeb\x69\xd2\x0d", 32))
        return BL_PATCH_APPLIED; // v1.0.4, fixed - SALT whitelabel

    // Unpatched bootloaders
    // ---------------------
    if (0 == memcmp(bl_hash, "\x63\x97\xc4\x46\xf6\xb9\x00\x2a\x8b\x15\x0b\xf4\xb9\xb4\xe0\xbb\x66\x80\x0e\xd0\x99\xb8\x81\xca\x49\x70\x01\x39\xb0\x55\x9f\x10", 32))
        return BL_HOTPATCHABLE; // v1.0.0, unpatched

    if (0 == memcmp(bl_hash, "\xd5\x44\xb5\xe0\x6b\x0c\x35\x5d\x68\xb8\x68\xac\x75\x80\xe9\xba\xb2\xd2\x24\xa1\xe2\x44\x08\x81\xcc\x1b\xca\x2b\x81\x67\x52\xd5", 32))
        return BL_HOTPATCHABLE; // v1.0.1, unpatched

    if (0 == memcmp(bl_hash, "\xcd\x70\x2b\x91\x02\x8a\x2c\xfa\x55\xaf\x43\xd3\x40\x7b\xa0\xf6\xf7\x52\xa4\xa2\xbe\x05\x83\xa1\x72\x98\x3b\x30\x3a\xb1\x03\x2e", 32))
        return BL_HOTPATCHABLE; // v1.0.2, unpatched

    if (0 == memcmp(bl_hash, "\x2e\x38\x95\x01\x43\xcf\x35\x03\x45\xa6\xdd\xad\xa4\xc0\xc4\xf2\x1e\xb2\xed\x33\x73\x09\xf3\x9c\x5d\xbc\x70\xb6\xc0\x91\xae\x00", 32))
        return BL_HOTPATCHABLE; // v1.0.3, unpatched

    if (0 == memcmp(bl_hash, "\xcb\x22\x25\x48\xa3\x9f\xf6\xcb\xe2\xae\x2f\x02\xc8\xd4\x31\xc9\xae\x0d\xf8\x50\xf8\x14\x44\x49\x11\xf5\x21\xb9\x5a\xb0\x2f\x4c", 32))
        return BL_HOTPATCHABLE; // v1.0.3_signed, unpatched

    if (0 == memcmp(bl_hash, "\x64\x65\xbc\x50\x55\x86\x70\x0a\x81\x11\xc4\xbf\x7d\xb6\xf4\x0a\xf7\x3e\x72\x0f\x9e\x48\x8d\x20\xdb\x56\x13\x5e\x5a\x69\x0c\x4f", 32))
        return BL_HOTPATCHABLE; // v1.0.3_signed, version generated from elf

    if (0 == memcmp(bl_hash, "\x77\x0b\x30\xaa\xa0\xbe\x88\x4e\xe8\x62\x18\x59\xf5\xd0\x55\x43\x7f\x89\x4a\x5c\x9c\x7c\xa2\x26\x35\xe7\x02\x4e\x05\x98\x57\xb7", 32))
        return BL_HOTPATCHABLE; // v1.0.4, unpatched - SALT whitelabel

    return BL_UNKNOWN;
#endif
}

/*
 * Hot-patch old bootloaders to disallow executing unsigned firmwares.
 *
 * \returns true iff this bootloader has been hotpatched
 */
static bool apply_hotpatch(void)
{
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
}

void check_bootloader(void) {
    enum BL_Kind kind = check_bootloader_kind();
    if (kind == BL_HOTPATCHABLE) {
        if (!apply_hotpatch()) {
            layout_warning_static("Hotpatch failed. Contact support.");
            shutdown();
        }
    } else if (kind == BL_UNKNOWN) {
        layout_warning_static("Unknown bootloader. Contact support.");
        shutdown();
    } else if (kind == BL_PATCH_APPLIED) {
        // do nothing, bootloader is already safe
    } else {
        layout_warning_static("B/L check failed. Reboot Device!");
        shutdown();
    }
}

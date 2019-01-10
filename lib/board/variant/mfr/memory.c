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


#include "keepkey/board/variant.h"

#ifndef EMULATOR
#  include <libopencm3/stm32/flash.h>
#else
#  include <stdio.h>
#endif

#include "keepkey/board/supervise.h"
#include "trezor/crypto/sha2.h"
#include "trezor/crypto/sha3.h"

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/keepkey_flash.h"

#include <string.h>
#include <assert.h>
#include <stdint.h>

uint8_t variant_mfr_sectorFromAddress(uint8_t *address) {
    uint32_t addr = (uint32_t)address;

    if (0x08000000 <= addr && addr <= 0x08003FFF) return  0;
    if (0x08004000 <= addr && addr <= 0x08007FFF) return  1;
    if (0x08008000 <= addr && addr <= 0x0800BFFF) return  2;
    if (0x0800C000 <= addr && addr <= 0x0800FFFF) return  3;
    if (0x08010000 <= addr && addr <= 0x0801FFFF) return  4;
    if (0x08020000 <= addr && addr <= 0x0803FFFF) return  5;
    if (0x08040000 <= addr && addr <= 0x0805FFFF) return  6;
    if (0x08060000 <= addr && addr <= 0x0807FFFF) return  7;
    if (0x08080000 <= addr && addr <= 0x0809FFFF) return  8;
    if (0x080A0000 <= addr && addr <= 0x080BFFFF) return  9;
    if (0x080C0000 <= addr && addr <= 0x080DFFFF) return 10;
    if (0x080E0000 <= addr && addr <= 0x080FFFFF) return 11;

#ifdef DEBUG_ON
    __builtin_unreachable();
#endif
    return 0;
}

void *variant_mfr_sectorStart(uint8_t sector) {
    switch (sector) {
#ifdef DEBUG_ON
    default: __builtin_unreachable();
#else
    default: return (void*)0x08000000;
#endif
    case  0: return (void*)0x08000000;
    case  1: return (void*)0x08004000;
    case  2: return (void*)0x08008000;
    case  3: return (void*)0x0800C000;
    case  4: return (void*)0x08010000;
    case  5: return (void*)0x08020000;
    case  6: return (void*)0x08040000;
    case  7: return (void*)0x08060000;
    case  8: return (void*)0x08080000;
    case  9: return (void*)0x080A0000;
    case 10: return (void*)0x080C0000;
    case 11: return (void*)0x080E0000;
    }
}

uint32_t variant_mfr_sectorLength(uint8_t sector) {
    switch (sector) {
#ifdef DEBUG_ON
    default: __builtin_unreachable();
#else
    default: return     0x0;
#endif
    case  0: return  0x4000;
    case  1: return  0x4000;
    case  2: return  0x4000;
    case  3: return  0x4000;
    case  4: return 0x10000;
    case  5: return 0x20000;
    case  6: return 0x20000;
    case  7: return 0x20000;
    case  8: return 0x20000;
    case  9: return 0x20000;
    case 10: return 0x20000;
    case 11: return 0x20000;
    }
}

bool variant_mfr_flashWrite(uint8_t *dst, uint8_t *src, size_t len, bool erase)
{
#ifndef EMULATOR
    // Don't allow writing outside of flash.
    if (dst < (uint8_t*)FLASH_ORIGIN ||
        (uint8_t*)FLASH_END < dst + len)
        return false;

    int sector = variant_mfr_sectorFromAddress(dst);

    // Don't allow writing over sector boundaries.
    if (variant_mfr_sectorLength(sector) < (uint8_t*)dst -
                                  (uint8_t*)variant_mfr_sectorStart(sector) + len)
        return false;

    // Don't allow writing to the bootstrap sector, it should be R/O
    if (FLASH_BOOTSTRAP_SECTOR == sector)
        return false;

    // Don't allow writing to the bootloader sectors, they should be R/0
    if (FLASH_BOOT_SECTOR_FIRST <= sector &&
        sector <= FLASH_BOOT_SECTOR_LAST)
        return false;

    uint8_t *dst_s = dst;
    uint8_t *dst_e = dst + len;
    const uint8_t *fw_s = (const uint8_t *)FLASH_APP_START;
    const uint8_t *fw_e = fw_s + *((const uint32_t*)FLASH_META_CODELEN);

    // In order to prevent us from accidentally overwriting the
    // currently-executing code, check that:

    // 1) The write doesn't overlap the beginning of the application data.
    if (dst_s <= fw_s && fw_s <= dst_e)
        return false;

    // 2) The write isn't fully contained within the application data.
    if (fw_s <= dst_s && dst_e <= fw_e)
        return false;

    // 3) The write doesn't overlap the end of the application data.
    if (dst_s <= fw_e && fw_e <= dst_e)
        return false;

    // 4) The write doesn't fully contain the application data.
    if (dst_s <= fw_s && fw_e <= dst_e)
        return false;

    if (erase) {
        // Erase the whole sector.
        svc_flash_erase_sector((uint32_t)variant_mfr_sectorFromAddress(dst));
    }

    // Write into the sector.
    return svc_flash_pgm_blk((uint32_t)dst, (uint32_t)src, len);
#else
    return false;
#endif
}

bool variant_mfr_flashHash(uint8_t *address, size_t address_len,
                            uint8_t *nonce, size_t nonce_len,
                            uint8_t *hash, size_t hash_len) {
#ifndef EMULATOR
    // Is address+len outside of flash?
    if (address < (uint8_t*)FLASH_ORIGIN ||
        (uint8_t*)FLASH_END < address + address_len)
      return false;

    // Is sha3_Final going to write off the end of hash?
    if (hash_len < 32)
      return false;

    static struct SHA3_CTX ctx;
    sha3_256_Init(&ctx);
    if (nonce) {
        sha3_Update(&ctx, nonce, nonce_len);
    }
    sha3_Update(&ctx, (void*)address, address_len);
    sha3_Final(&ctx, hash);
    return true;
#else
    return false;
#endif
}

void variant_mfr_flashDump(uint8_t *dst, uint8_t *src, size_t len) {
    memcpy(dst, src, len);
}

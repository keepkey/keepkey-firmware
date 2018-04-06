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

/* === Includes ============================================================ */


#ifndef EMULATOR
#  include <libopencm3/stm32/flash.h>
#else
#  include <stdio.h>
#endif

#include "keepkey/crypto/sha2.h"
#include "keepkey/crypto/sha3.h"

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/keepkey_flash.h"

#include <string.h>
#include <assert.h>
#include <stdint.h>


/* === Functions =========================================================== */

/*
 * memory_protect() - Set option bytes for memory pretection
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void memory_protect(void)
{
#ifndef EMULATOR
    /*                     set RDP level 2                   WRP for sectors 0,5,6  */
    if((((*OPTION_BYTES_1) & 0xFFFF) == OPTION_RDP) && (((*OPTION_BYTES_2) & 0xFFFF) == OPTION_WRP))
    {
        return; // already set up correctly - bail out
    }

    flash_unlock_option_bytes();
    /*                              WRP +    RDP */
    flash_program_option_bytes((uint32_t)OPTION_WRP << 16 | OPTION_RDP);  //RDP BLevel 2 (Irreversible)
    flash_lock_option_bytes();
#else
    printf("memory protect ON\n");
#endif
}

int memory_bootloader_hash(uint8_t *hash, bool cached)
{
    static uint8_t cached_hash[SHA256_DIGEST_LENGTH];

    if(cached_hash[0] == '\0' || !cached)
    {
        sha256_Raw((const uint8_t *)FLASH_BOOT_START, FLASH_BOOT_LEN, cached_hash);
        sha256_Raw(cached_hash, SHA256_DIGEST_LENGTH, cached_hash);
    }

    memcpy(hash, cached_hash, SHA256_DIGEST_LENGTH);

    return SHA256_DIGEST_LENGTH;
}

/*
 * memory_firmware_hash() - SHA256 hash of firmware (meta and application)
 *
 * INPUT
 *     - hash: buffer to be filled with hash
 * OUTPUT
 *     none
 */
int memory_firmware_hash(uint8_t *hash)
{
    SHA256_CTX ctx;
    uint32_t codelen = *((uint32_t *)FLASH_META_CODELEN);

    if(codelen <= FLASH_APP_LEN)
    {
        sha256_Init(&ctx);
        sha256_Update(&ctx, (const uint8_t *)META_MAGIC_STR, META_MAGIC_SIZE);
        sha256_Update(&ctx, (const uint8_t *)FLASH_META_CODELEN,
                      FLASH_META_DESC_LEN - META_MAGIC_SIZE);
        sha256_Update(&ctx, (const uint8_t *)FLASH_APP_START, codelen);
        sha256_Final(&ctx, hash);
        return SHA256_DIGEST_LENGTH;
    }
    else
    {
        return 0;
    }
}

/*
 * memory_storage_hash() - SHA256 hash of storage area
 *
 * INPUT
 *     - hash: buffer to be filled with hash
 *     - storage_location: current storage location (changes due to wear leveling)
 * OUTPUT
 *     none
 */
int memory_storage_hash(uint8_t *hash, Allocation storage_location)
{
    const uint8_t *storage_location_start;
    storage_location_start = (const uint8_t *)flash_write_helper(storage_location);

    sha256_Raw(storage_location_start, sizeof(ConfigFlash), hash);
    return SHA256_DIGEST_LENGTH;
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
bool find_active_storage(Allocation *storage_location)
{
    bool ret_stat = false;
    Allocation storage_location_use;
    size_t storage_location_start;

    /* Find 1st storage sector with valid data */
    for(storage_location_use = FLASH_STORAGE1; storage_location_use <= FLASH_STORAGE3;
            storage_location_use++)
    {
        storage_location_start = flash_write_helper(storage_location_use);

        if(memcmp((void *)storage_location_start, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN) == 0)
        {
            /* Found valid data.  Load data and exit */
            *storage_location = storage_location_use;
            ret_stat = true;
            break;
        }
    }

    return(ret_stat);
}

#ifdef MANUFACTURER
uint8_t sector_from_address(uint8_t *address) {
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

void *sector_start(uint8_t sector) {
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

uint32_t sector_length(uint8_t sector) {
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

bool memory_flash_write(uint8_t *dst, uint8_t *src, size_t len, bool erase)
{
    // Don't allow writing outside of flash.
    if (dst < (uint8_t*)FLASH_ORIGIN ||
        (uint8_t*)FLASH_END < dst + len)
        return false;

    int sector = sector_from_address(dst);

    // Don't allow writing over sector boundaries.
    if (sector_length(sector) < (uint8_t*)dst -
                                (uint8_t*)sector_start(sector) + len)
        return false;

    // Don't allow writing to the bootstrap sector, it should be R/O
    if (FLASH_BOOTSTRAP_SECTOR_FIRST <= sector &&
        sector <= FLASH_BOOTSTRAP_SECTOR_LAST)
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

    // 3) The write doesn't overlap the end of the application data.
    if (dst_s <= fw_e && fw_e <= dst_e)
        return false;

    // 4) The write doesn't fully contain the application data.
    if (dst_s <= fw_s && fw_e <= dst_e)
        return false;

    // Tell the flash we're about to write to it.
    flash_unlock();

    if (erase) {
        // Erase the whole sector.
        flash_erase_sector(sector_from_address(dst), 0 /* 8-bit writes */);
    }

    // Write into the sector.
    flash_program((uint32_t)dst, src, len);

    // Disallow writing to flash.
    flash_lock();

    // Check for any errors.
    return flash_chk_status();
}

bool memory_flash_hash(uint8_t *address, size_t address_len,
                       uint8_t *nonce, size_t nonce_len,
                       uint8_t *hash, size_t hash_len) {

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
}
#endif


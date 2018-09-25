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

#include "trezor/crypto/sha2.h"
#include "trezor/crypto/sha3.h"

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/keepkey_flash.h"

#include <string.h>
#include <assert.h>
#include <stdint.h>

#ifdef EMULATOR
uint8_t *emulator_flash_base = NULL;
#endif


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

void memory_unlock(void) {
#ifndef EMULATOR
    // This exercises a bug in the STM32F2 that allows writing to read-only
    // sectors of flash.
    flash_unlock_option_bytes();
    
#ifdef DEBUG_ON
    // 0xFFFAAEC: remove wp from all sectors, no RDP (unless previously set to level 2 which is irreversible), 
    // disable configurable resets. Low order two bits are don't care.
    flash_program_option_bytes(0x0FFFAAEC);
#else
    // Even though level 2 is described as sticky, this chip has a proven bug related to this register so 
    // to be sure rewrite the level two value for RDP for non-debug builds.
    flash_program_option_bytes(0x0FFFCCEC);
#endif

    flash_lock_option_bytes();
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
#ifndef EMULATOR
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
#else
    return 0;
#endif
}

const char *memory_firmware_hash_str(char digest[SHA256_DIGEST_STRING_LENGTH])
{
#ifndef EMULATOR
    SHA256_CTX ctx;
    uint32_t codelen = *((uint32_t *)FLASH_META_CODELEN);

    if(codelen <= FLASH_APP_LEN)
    {
        sha256_Init(&ctx);
        sha256_Update(&ctx, (const uint8_t *)META_MAGIC_STR, META_MAGIC_SIZE);
        sha256_Update(&ctx, (const uint8_t *)FLASH_META_CODELEN,
                      FLASH_META_DESC_LEN - META_MAGIC_SIZE);
        sha256_Update(&ctx, (const uint8_t *)FLASH_APP_START, codelen);
        sha256_End(&ctx, digest);
        return &digest[0];
    }
    else
    {
        return "No Firmware";
    }
#else
    return "No Firmware";
#endif
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

    sha256_Raw(storage_location_start, STORAGE_SECTOR_LEN, hash);
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


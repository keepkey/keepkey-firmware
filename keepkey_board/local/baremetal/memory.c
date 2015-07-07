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

#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <libopencm3/stm32/flash.h>
#include <sha2.h>
#include <keepkey_board.h>
#include <memory.h>
#include <keepkey_flash.h>

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
    /*                     set RDP level 2                   WRP for sectors 0,5,6  */
    if((((*OPTION_BYTES_1) & 0xFFFF) == OPTION_RDP) && (((*OPTION_BYTES_2) & 0xFFFF) == OPTION_WRP))
    {
        return; // already set up correctly - bail out
    }

    flash_unlock_option_bytes();
    /*                              WRP +    RDP */
    flash_program_option_bytes((uint32_t)OPTION_WRP << 16 | OPTION_RDP);  //RDP BLevel 2 (Irreversible)
    flash_lock_option_bytes();
}

/*
 * memory_bootloader_hash() - SHA256 hash of bootloader
 *
 * INPUT
 *     - hash: buffer to be filled with hash
 * OUTPUT
 *     none
 */
int memory_bootloader_hash(uint8_t *hash)
{
    static uint8_t cached_hash[SHA256_DIGEST_LENGTH];

    if(cached_hash[0] == '\0')
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
        sha256_Final(hash, &ctx);
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
 * OUTPUT
 *     none
 */
int memory_storage_hash(uint8_t *hash)
{
    const uint8_t *st_start;
    st_start = (const uint8_t *)get_storage_loc_start();

    sha256_Raw(st_start, sizeof(ConfigFlash), hash);
    return SHA256_DIGEST_LENGTH;
}

/*
 * find_active_storage_sect() - find a sector with valid data
 *
 * INPUT - 
 *      pointer to save config data
 * OUTPUT - 
 *      status
 *
 */
bool find_active_storage_sect(FlashSector *st_ptr)
{
    bool ret_stat = false; 
    Allocation st_use;
    size_t st_start;
    
    /*find 1st storage sector /w valid data */
    for(st_use = FLASH_STORAGE1; st_use <= FLASH_STORAGE3; st_use++)
    {
        st_start = flash_write_helper(st_use);

        if(memcmp((void *)st_start, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN) == 0)
        {
            /* found valid data.  load data and exit */
            st_ptr->start = st_start;
            st_ptr->use = st_use;
            ret_stat = true;
            break;
        }
    }
    return(ret_stat);
}

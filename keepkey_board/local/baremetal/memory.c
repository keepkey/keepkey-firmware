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
#include <sha3.h>

#include "keepkey_board.h"
#include "memory.h"
#include "keepkey_flash.h"

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
bool memory_flash_write(uint8_t *address, uint8_t *data, size_t data_len) {

    flash_unlock();
    flash_program((uint32_t)address, data, data_len);
    flash_lock();

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


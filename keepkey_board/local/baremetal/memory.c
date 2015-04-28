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
 *
 *
 * March 19, 2015 - This file has been modified and adapted for KeepKey project.
 *
 */

#include <string.h>

#include <assert.h>
#include <stdint.h>
#include <libopencm3/stm32/flash.h>
#include <sha2.h>
#include <memory.h>

#define OPTION_BYTES_1 ((uint64_t *)0x1FFFC000)
#define OPTION_BYTES_2 ((uint64_t *)0x1FFFC008)

void memory_protect(void)
{
    //                     set RDP level 2                   WRP for sectors 0 and 1
    if((((*OPTION_BYTES_1) & 0xFFFF) == 0xCCFF) && (((*OPTION_BYTES_2) & 0xFFFF) == 0xFF88))
    {
        return; // already set up correctly - bail out
    }

    flash_unlock_option_bytes();
    //                              WRP +    RDP
    flash_program_option_bytes(0xFF880000 + 0xCCFF);  //RDP BLevel 2 (Irreversible)
    flash_lock_option_bytes();
}

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

int memory_app_fingerprint(uint8_t *digest)
{
    uint32_t codelen = *((uint32_t *)FLASH_META_CODELEN);

    if(codelen <= FLASH_APP_LEN)
    {
        sha256_Raw((const uint8_t *)FLASH_APP_START, codelen, digest);
        return SHA256_DIGEST_LENGTH;
    }
    else
    {
        return 0;
    }
}

int memory_storage_fingerprint(uint8_t *digest, size_t len)
{
    sha256_Raw((const uint8_t *)FLASH_STORAGE_START, len, digest);
    return SHA256_DIGEST_LENGTH;
}
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
 * Jan 9, 2015 - This file has been modified and adapted for KeepKey project.
 *
 */

#include <assert.h>
#include <stdint.h>

#include <libopencm3/stm32/flash.h>
#include <sha2.h>

#include "memory.h"

#define OPTION_BYTES_1 ((uint64_t *)0x1FFFC000)
#define OPTION_BYTES_2 ((uint64_t *)0x1FFFC008)

void memory_protect(void)
{
    //                     set RDP level 2                   WRP for sectors 0 and 1
    if ((((*OPTION_BYTES_1) & 0xFFFF) == 0xCCFF) && (((*OPTION_BYTES_2) & 0xFFFF) == 0xFFFC)) {
        return; // already set up correctly - bail out
    }
    flash_unlock_option_bytes();
    //                                 WRP +    RDP
    flash_program_option_bytes( 0xFFFC0000 + 0xCCFF);
    flash_lock_option_bytes();
}

int memory_bootloader_hash(uint8_t *hash)
{
    const size_t hash_len = 32;
    sha256_Raw((const uint8_t *)FLASH_BOOT_START, FLASH_BOOT_LEN, hash);
    sha256_Raw(hash, hash_len, hash);
    return hash_len;
}


void flash_erase(Allocation group)
{
    //TODO: See if there's a way to handle flash errors here gracefully.

    const FlashSector* s = flash_sector_map;
    while(s->use != FLASH_INVALID)
    {
        if(s->use == group)
        {
            flash_erase_sector(s->sector, FLASH_CR_PROGRAM_X8);
        }

        ++s;
    }
}

static size_t flash_write_helper(Allocation group, size_t offset, size_t len)
{
	size_t start = 0;
	const FlashSector* s = flash_sector_map;
	while(s->use != FLASH_INVALID)
	{
		if(s->use == group)
		{
			start = s->start;
			break;
		}
		++s;
	}

	assert(start != 0);

	return start;
}

void flash_write(Allocation group, size_t offset, size_t len, uint8_t* data)
{
	size_t start = flash_write_helper(group, offset, len);
	flash_program(start + offset, data, len);
}

void flash_write_with_progress(Allocation group, size_t offset, size_t len, uint8_t* data, progress_handler_t ph)
{

	size_t start = flash_write_helper(group, offset, len);
	for (int i = 0; i < len; i++) {
		(*ph)();
		flash_program_byte(start + offset+i, data[i]);
	}
}

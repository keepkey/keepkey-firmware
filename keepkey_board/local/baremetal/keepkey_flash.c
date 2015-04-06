/* START KEEPKEY LICENSE */
/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2015 KeepKey LLC
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
 */
/* END KEEPKEY LICENSE */


#include <stdint.h>
#include <libopencm3/stm32/flash.h>
#include <keepkey_flash.h>
#include <string.h>

/*
 * flash_write_helper - helper function to locate starting address of the functional group
 * 
 * INPUT : 
 *      1. functional group
 * OUTPUT:
 *      starting address of functional group
 */
static uint32_t flash_write_helper(Allocation group)
{
	uint32_t start = 0;
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
	return start;
}

/*
 * flash_erase_word() - flash erase in word (32bit) size
 *
 * INPUT : 
 *     functional group 
 * OUTPUT : 
 *     none
 */
void flash_erase_word(Allocation group)
{
    //TODO: See if there's a way to handle flash errors here gracefully.
    const FlashSector* s = flash_sector_map;
    while(s->use != FLASH_INVALID)
    {
        if(s->use == group) {
            flash_erase_sector(s->sector, FLASH_CR_PROGRAM_X32);
        }
        ++s;
    }
}

/*
 * flash_erase - flash erase in byte size
 *
 * INPUT : 
 *     functional group 
 * OUTPUT : 
 *     none
 */
void flash_erase(Allocation group)
{
    //TODO: See if there's a way to handle flash errors here gracefully.

    const FlashSector* s = flash_sector_map;
    while(s->use != FLASH_INVALID)
    {
        if(s->use == group) {
            flash_erase_sector(s->sector, FLASH_CR_PROGRAM_X8);
        }
        ++s;
    }
}

/*
 * flash_write_word - flash write in word (32bit) size
 *
 * INPUT : 
 *      1. functional group
 *      2. flash address offset
 *      3. length of source data
 *      4. pointer to source data 
 * OUTPUT:
 *      status 
 */
bool flash_write_word(Allocation group, uint32_t offset, uint32_t len, uint8_t *data)
{
    bool retval = true;
	uint32_t start = flash_write_helper(group);
    uint32_t data_word[1];
    uint32_t i, align_cnt = 0;

    start += offset ;

    /* Byte writes for flash start address not long-word aligned */
    if(start % sizeof(uint32_t)) {
        align_cnt = sizeof(uint32_t) - start % sizeof(uint32_t);
        flash_program(start, data, align_cnt);
        start += align_cnt;
        data += align_cnt;
        len -= align_cnt;
    }

    /* Long word writes */
    for(i = 0 ; i < len/sizeof(uint32_t); i++)
    {
        memcpy(data_word, data, sizeof(uint32_t));
	    flash_program_word(start, *data_word);
        start += sizeof(uint32_t);
        data += sizeof(uint32_t);
	    // check flash status register for error condition
	    if (FLASH_SR & (FLASH_SR_PGAERR | FLASH_SR_PGPERR | FLASH_SR_PGSERR | FLASH_SR_WRPERR)) {
            retval = false;
            goto fww_exit;
	    }
    }

    /* Byte write for last remaining bytes */
    align_cnt = len % sizeof(uint32_t);
    if(align_cnt) {
        flash_program(start, data, align_cnt);
    }
fww_exit:
    return(retval);
}

/*
 * flash_write - flash write in byte size
 *
 * INPUT : 
 *      1. functional group
 *      2. flash address offset
 *      3. length of source data
 *      4. source data address
 * OUTPUT:
 *      none
 */
//TODO : replace all calls to this function with flash_write_word() to speed up the flash write.
void flash_write(Allocation group, uint32_t offset, uint32_t len, uint8_t* data)
{
	uint32_t start = flash_write_helper(group);
	flash_program(start + offset, data, len);
}










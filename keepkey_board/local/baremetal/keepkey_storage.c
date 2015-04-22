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

#include <libopencm3/stm32/flash.h>
#include <keepkey_board.h>
#include <memory.h>

/*
 * storage_from_flash() - copy configuration from storage partition in flash memory to shadow memory in RAM
 *
 * INPUT -
 *      storage version
 * OUTPUT -
 *      true/false status
 *
 */
bool storage_get_end_stor(void *stor_cpy)
{
	/* make a copy of the storage data */
	memcpy(stor_cpy, (void *)FLASH_STORAGE_START, sizeof(ConfigFlash));
    return true;
}

#if DEBUG_LINK
/*
 * storage_get_end_stor_cnt() - search through configuration node list to find the end node,
 *                  	and returns the count of nodes.
 *
 * INPUT :
 *      pointer to storage end node.
 * OUTPUT :
 *      true/false : status
 */
uint32_t storage_get_end_stor_cnt(void)
{
    uint32_t cnt = 0;

    /* set to head node for start of search*/
    ConfigFlash *config_ptr = (ConfigFlash*)FLASH_STORAGE_START;

    /* search through the node list to find the last node (active node) */
	while(memcmp((void *)config_ptr->meta.magic , STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN) == 0) {
        config_ptr++;
        cnt++;
    }

    return(cnt);
}

#endif





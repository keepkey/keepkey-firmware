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
 * Jan 13, 2015 - This file has been modified and adapted for KeepKey project.
 *
 */

#ifndef KEEPKEY_FLASH_H
#define KEEPKEY_FLASH_H

#include <stddef.h>
#include <memory.h>

/* declarations */
void flash_erase(Allocation group);
void flash_erase_word(Allocation group);
bool flash_write(Allocation group, uint32_t offset, uint32_t len, uint8_t* data);
bool flash_write_word(Allocation group, uint32_t offset, uint32_t len, uint8_t* data);
bool flash_chk_status(void);


#endif

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
 */

#ifndef KEEPKEY_FLASH_H
#define KEEPKEY_FLASH_H


#define MODEL_STR_SIZE  32


#include <stddef.h>

#include "memory.h"


intptr_t flash_write_helper(Allocation group);
void flash_erase(Allocation group);
void flash_erase_word(Allocation group);
bool flash_write(Allocation group, uint32_t offset, uint32_t len, uint8_t* data);
bool flash_write_word(Allocation group, uint32_t offset, uint32_t len, uint8_t* data);
bool flash_chk_status(void);
bool is_mfg_mode(void);
bool set_mfg_mode_off(void);
const char *flash_getModel(void);
bool flash_setModel(const char (*model)[32]);
const char *flash_programModel(void);
#endif

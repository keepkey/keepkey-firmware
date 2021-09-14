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

#ifndef STORAGE_H
#define STORAGE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define STORAGE_RETRIES 3
#define FLASH_STORAGE_META_LEN 44

/// \brief Validate storage content and copy data to shadow memory.
bool storage_read(uint8_t* buf, size_t len);

/// \brief Clear storage.
void storage_wipe(void);

/// \brief Write content of configuration in shadow memory to storage partion
///        in flash.
bool storage_write(const uint8_t* buf, size_t len);

#endif

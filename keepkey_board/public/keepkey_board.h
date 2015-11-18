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

#ifndef KEEPKEY_BOARD_H
#define KEEPKEY_BOARD_H

/* === Includes ============================================================ */

#include <storage.pb.h>
#include <bip32.h>

#include "keepkey_leds.h"
#include "keepkey_display.h"
#include "keepkey_button.h"
#include "layout.h"
#include "timer.h"
#include "usb_driver.h"

/*
 storage layout:

 offset | type/length |  description
--------+-------------+-------------------------------
 0x0000 |  4 bytes    |  magic = 'stor'
 0x0004 |  12 bytes   |  uuid
 0x0010 |  25 bytes   |  uuid_str
 0x0029 |  ?          |  Storage structure
 */

/* === Defines ============================================================= */

#define STORAGE_MAGIC_STR   "stor"
#define STORAGE_MAGIC_LEN   4

#define CACHE_EXISTS        0xCA

/* Specify the length of the uuid binary string */
#define STORAGE_UUID_LEN    12

/* Length of the uuid binary converted to readable ASCII.  */
#define STORAGE_UUID_STR_LEN ((STORAGE_UUID_LEN * 2) + 1)

#define SMALL_STR_BUF       32
#define MEDIUM_STR_BUF      64
#define LARGE_STR_BUF       128

#define VERSION_NUM(x) #x
#define VERSION_STR(x) VERSION_NUM(x)

/* === Typedefs ============================================================ */

/* Flash metadata structure which will contains unique identifier
   information that spans device resets.  */
typedef struct
{
    char magic[STORAGE_MAGIC_LEN];
    uint8_t uuid[STORAGE_UUID_LEN];
    char uuid_str[STORAGE_UUID_STR_LEN];
} Metadata;

/* Cache structure */
typedef struct
{
    /* Root node cache */
    uint8_t root_node_cache_status;
    HDNode root_node_cache;
} Cache;

/* Config flash overlay structure.  */
typedef struct
{
    Metadata meta;
    Storage storage;
    Cache cache;
} ConfigFlash;

/* === Variables =========================================================== */

extern uintptr_t __stack_chk_guard;

/* === Functions =========================================================== */

void __attribute__((noreturn)) system_halt(void);
void board_reset(void);
void board_init(void);
void reset_rng(void);

void __stack_chk_fail(void) __attribute__((noreturn));
uint32_t calc_crc32(uint32_t *data, int word_len);

#endif

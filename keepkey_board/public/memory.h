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

#ifndef __MEMORY_H__
#define __MEMORY_H__

#include <stddef.h>

/*

 flash memory layout:

   name    |          range          |  size   |     function
-----------+-------------------------+---------+------------------
 Sector  0 | 0x08000000 - 0x08003FFF |  16 KiB | bootloader code
 Sector  1 | 0x08004000 - 0x08007FFF |  16 KiB | bootloader code
-----------+-------------------------+---------+------------------
 Sector  2 | 0x08008000 - 0x0800BFFF |  16 KiB | bootloader code
 Sector  3 | 0x0800C000 - 0x0800FFFF |  16 KiB | bootloader code
-----------+-------------------------+---------+------------------
 Sector  4 | 0x08010000 - 0x0801FFFF |  64 KiB | storage/config
 Sector  5 | 0x08020000 - 0x0803FFFF | 128 KiB | application code
 Sector  6 | 0x08040000 - 0x0805FFFF | 128 KiB | application code
 Sector  7 | 0x08060000 - 0x0807FFFF | 128 KiB | application code
===========+=========================+============================
 Sector  8 | 0x08080000 - 0x0809FFFF | 128 KiB | application code
 Sector  9 | 0x080A0000 - 0x080BFFFF | 128 KiB | application code
 Sector 10 | 0x080C0000 - 0x080DFFFF | 128 KiB | application code
 Sector 11 | 0x080E0000 - 0x080FFFFF | 128 KiB | application code

 metadata area:

 offset | type/length |  description
--------+-------------+-------------------------------
 0x0000 |  4 bytes    |  magic = 'KK01'
 0x0004 |  uint32     |  length of the code (codelen)
 0x0008 |  uint8      |  signature index #1
 0x0009 |  uint8      |  signature index #2
 0x000A |  uint8      |  signature index #3
 0x000B |  uint8      |  flags
 0x000C |  52 bytes   |  reserved
 0x0040 |  64 bytes   |  signature #1
 0x0080 |  64 bytes   |  signature #2
 0x00C0 |  64 bytes   |  signature #3
 0x0100 |  32K-256 B  |  persistent storage

 flags & 0x01 -> restore storage after flashing (if signatures are ok)
 */

#define FLASH_ORIGIN		(0x08000000)
#define FLASH_TOTAL_SIZE	(1024 * 1024)
#define FLASH_END               (FLASH_ORIGIN + FLASH_TOTAL_SIZE)

#define FLASH_BOOT_START	(FLASH_ORIGIN)
#define FLASH_BOOT_LEN		(0x20000)

#define FLASH_CONFIG_START	(FLASH_BOOT_START + FLASH_BOOT_LEN)
#define FLASH_CONFIG_LEN	(0x20000)

#define FLASH_APP_START		(FLASH_CONFIG_START + FLASH_CONFIG_LEN)

#define FLASH_CONFIG_DESC_LEN   (0x100)

#define FLASH_STORAGE_START	(FLASH_CONFIG_START + FLASH_CONFIG_DESC_LEN)
#define FLASH_STORAGE_LEN	(FLASH_APP_START - FLASH_STORAGE_START)

#define FLASH_BOOT_SECTOR_FIRST	0
#define FLASH_BOOT_SECTOR_LAST	4

#define FLASH_CONFIG_SECTOR_FIRST	5
#define FLASH_CONFIG_SECTOR_LAST	5

#define FLASH_APP_SECTOR_FIRST	6
#define FLASH_APP_SECTOR_LAST	11


/**
 * Flash sector map definition to simplify flash management operations.
 */
typedef enum
{
    FLASH_INVALID,
    FLASH_BOOTLOADER,
    FLASH_CONFIG,
    FLASH_APP
} Allocation;

typedef struct 
{
    int sector;
    size_t start;
    uint32_t len;
    Allocation use;
} FlashSector;

static const FlashSector flash_sector_map[]= {
    { 0,  0x08000000, 0x4000,  FLASH_BOOTLOADER },
    { 1,  0x08004000, 0x4000,  FLASH_BOOTLOADER },
    { 2,  0x08008000, 0x4000,  FLASH_BOOTLOADER },
    { 3,  0x0800c000, 0x4000,  FLASH_BOOTLOADER },
    { 4,  0x08010000, 0x10000, FLASH_BOOTLOADER },
    { 5,  0x08020000, 0x20000, FLASH_CONFIG },
    { 6,  0x08040000, 0x20000, FLASH_APP },
    { 7,  0x08060000, 0x20000, FLASH_APP },
    { 8,  0x08080000, 0x20000, FLASH_APP },
    { 9,  0x080A0000, 0x20000, FLASH_APP },
    { 10, 0x080C0000, 0x20000, FLASH_APP },
    { 11, 0x080E0000, 0x20000, FLASH_APP },
    { -1, 0,          0,       FLASH_INVALID}
};

void flash_erase(Allocation group);
void flash_write(Allocation group, size_t offset, size_t len, uint8_t* data);
void flash_write_ticking(Allocation group, size_t offset, size_t len, uint8_t* data, void (*tick)());

void memory_protect(void);
int memory_bootloader_hash(uint8_t *hash);


#endif

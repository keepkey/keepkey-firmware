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

#ifndef MEMORY_H
#define MEMORY_H

//#include <libopencm3/cm3/mpu.h>
#include "trezor/crypto/sha2.h"

#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>


/*

 flash memory layout:
 --------------------
   name    |          range          |  size   |     function     |   MPU Protection
-----------+-------------------------+---------+------------------+----------------------
 Sector  0 | 0x08000000 - 0x08003FFF |  16 KiB | bootstrap code   |  signature dependent
 Sector  1 | 0x08004000 - 0x08007FFF |  16 KiB | storage/config   |     full access
-----------+-------------------------+---------+------------------+----------------------
 Sector  2 | 0x08008000 - 0x0800BFFF |  16 KiB | storage/config   |     full access
 Sector  3 | 0x0800C000 - 0x0800FFFF |  16 KiB | storage/config   |     full access
-----------+-------------------------+---------+------------------+----------------------
 Sector  4 | 0x08010000 - 0x0801FFFF |  64 KiB | empty            |     full access
 Sector  5 | 0x08020000 - 0x0803FFFF | 128 KiB | bootloader code  |  signature dependent
 Sector  6 | 0x08040000 - 0x0805FFFF | 128 KiB | bootloader code  |  signature dependent
 Sector  7 | 0x08060000 - 0x0807FFFF | 128 KiB | application code |     full access
 Sector  8 | 0x08080000 - 0x0809FFFF | 128 KiB | application code |     full access
 Sector  9 | 0x080A0000 - 0x080BFFFF | 128 KiB | application code |     full access
 Sector 10 | 0x080C0000 - 0x080DFFFF | 128 KiB | application code |     full access
 Sector 11 | 0x080E0000 - 0x080FFFFF | 128 KiB | application code |     full access

 Application metadata area:
 -------------------------
 offset | type/length |  description
--------+-------------+-------------------------------
 0x0000 |  4 bytes    |  magic = 'KPKY'
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




#ifdef EMULATOR
extern uint8_t *emulator_flash_base;
#define FLASH_PTR(x)		(emulator_flash_base + (x - FLASH_ORIGIN))
#else
#define FLASH_PTR(x)		(const uint8_t*) (x)
#endif

#define OPTION_BYTES_1 ((uint64_t *)0x1FFFC000)
#define OPTION_BYTES_2 ((uint64_t *)0x1FFFC008)
#define OPTION_RDP 0xCCFF
#define OPTION_WRP 0xFF9E

#define OTP_MFG_ADDR            0x1FFF7800
#define OTP_MFG_SIG             0x08012015
#define OTP_MFG_SIG_LEN         4
#define OTP_MODEL_ADDR          0x1FFF7820
#define OTP_BLK_LOCK(x)         (0x1FFF7A00 + (x - 0x1FFF7800)/0x20)

#define BSTRP_FLASH_SECT_LEN    0x4000
#define STOR_FLASH_SECT_LEN     0x4000
#define UNUSED_FLASH_SECT0_LEN  0x10000 
#define BLDR_FLASH_SECT_LEN     0x20000
#define APP_FLASH_SECT_LEN      0x20000

#define BSTRP_FLASH_SECT_START  0x08000000
#define BLDR_FLASH_SECT_START   0x08020000


/* meta info */
#define META_MAGIC_STR          "KPKY"

/* Flash Info */
#define FLASH_ORIGIN            (0x08000000)
#define FLASH_TOTAL_SIZE        (1024 * 1024)
#define FLASH_END               (FLASH_ORIGIN + FLASH_TOTAL_SIZE)

/* Boot Strap Partition */
#define FLASH_BOOTSTRAP_START   (FLASH_ORIGIN)     //0x0800_0000 - 0x0800_3FFF
#define FLASH_BOOTSTRAP_LEN     (0x4000)

/* Storage/Configuration Partition */

#define FLASH_STORAGE_LEN       (0x4000)

/*<  0x801_0000 - 0x801_FFFF is empty  >*/

/* Boot Loader Partition */
#define FLASH_BOOT_START        (0x08020000)                          //0x0802_0000 - 0x0805_FFFF
#define FLASH_BOOT_LEN          (0x40000)


/* Application Partition */
#define FLASH_META_START        (FLASH_BOOT_START + FLASH_BOOT_LEN) //0x0806_0000
#define FLASH_META_DESC_LEN     (0x100)

#define FLASH_META_MAGIC        (FLASH_META_START)
#define FLASH_META_CODELEN      (FLASH_META_MAGIC       + sizeof(((app_meta_td *)NULL)->magic))
#define FLASH_META_SIGINDEX1    (FLASH_META_CODELEN     + sizeof(((app_meta_td *)NULL)->code_len))
#define FLASH_META_SIGINDEX2    (FLASH_META_SIGINDEX1   + sizeof(((app_meta_td *)NULL)->sig_index1))
#define FLASH_META_SIGINDEX3    (FLASH_META_SIGINDEX2   + sizeof(((app_meta_td *)NULL)->sig_index2))
#define FLASH_META_FLAGS        (FLASH_META_SIGINDEX3   + sizeof(((app_meta_td *)NULL)->sig_index3))
#define FLASH_META_RESERVE      (FLASH_META_FLAGS       + sizeof(((app_meta_td *)NULL)->flag))
#define FLASH_META_SIG1         (FLASH_META_RESERVE     + sizeof(((app_meta_td *)NULL)->rsv))
#define FLASH_META_SIG2         (FLASH_META_SIG1        + sizeof(((app_meta_td *)NULL)->sig1))
#define FLASH_META_SIG3         (FLASH_META_SIG2        + sizeof(((app_meta_td *)NULL)->sig2))


#define META_MAGIC_SIZE         (sizeof(((app_meta_td *)NULL)->magic))

#define FLASH_APP_START         (FLASH_META_START + FLASH_META_DESC_LEN)     //0x0806_0200 - 0x080F_FFFF
#define FLASH_APP_LEN           (FLASH_END - FLASH_APP_START)

#define SIG_FLAG                (*( uint8_t const *)FLASH_META_FLAGS)

/* Misc Info. */
#define FLASH_BOOTSTRAP_SECTOR 0

#define FLASH_BOOTSTRAP_SECTOR_FIRST   0
#define FLASH_BOOTSTRAP_SECTOR_LAST    0

#define FLASH_STORAGE_SECTOR_FIRST   1
#define FLASH_STORAGE_SECTOR_LAST    3

#define FLASH_VARIANT_SECTOR_FIRST 4
#define FLASH_VARIANT_SECTOR_LAST 4

#define FLASH_BOOT_SECTOR_FIRST 5
#define FLASH_BOOT_SECTOR_LAST  6

#define FLASH_APP_SECTOR_FIRST  7
#define FLASH_APP_SECTOR_LAST   11

#define STORAGE_SECT_DEFAULT FLASH_STORAGE1

/* Application Meta format */
typedef struct
{
    uint32_t magic;
    uint32_t code_len;
    uint8_t  sig_index1;
    uint8_t  sig_index2;
    uint8_t  sig_index3;
    uint8_t  flag;
    uint8_t  rsv[52];
    uint8_t  sig1[64];
    uint8_t  sig2[64];
    uint8_t  sig3[64];
} app_meta_td;

typedef enum
{
    FLASH_INVALID,
    FLASH_BOOTSTRAP,
    FLASH_STORAGE1,
    FLASH_STORAGE2,
    FLASH_STORAGE3,
    FLASH_UNUSED0,
    FLASH_BOOTLOADER,
    FLASH_APP
} Allocation;

typedef struct
{
    int sector;
    size_t start;
    uint32_t len;
    Allocation use;
} FlashSector;

typedef void (*progress_handler_t)(void);

static const FlashSector flash_sector_map[] =
{
    { 0,  0x08000000, BSTRP_FLASH_SECT_LEN, FLASH_BOOTSTRAP },
    { 1,  0x08004000, STOR_FLASH_SECT_LEN,  FLASH_STORAGE1  }, 
    { 2,  0x08008000, STOR_FLASH_SECT_LEN,  FLASH_STORAGE2  }, 
    { 3,  0x0800C000, STOR_FLASH_SECT_LEN,  FLASH_STORAGE3  },
    { 4,  0x08010000, UNUSED_FLASH_SECT0_LEN, FLASH_UNUSED0 },
    { 5,  0x08020000, BLDR_FLASH_SECT_LEN,  FLASH_BOOTLOADER },
    { 6,  0x08040000, BLDR_FLASH_SECT_LEN,  FLASH_BOOTLOADER },
    { 7,  0x08060000, APP_FLASH_SECT_LEN,   FLASH_APP },
    { 8,  0x08080000, APP_FLASH_SECT_LEN,   FLASH_APP },
    { 9,  0x080A0000, APP_FLASH_SECT_LEN,   FLASH_APP },
    { 10, 0x080C0000, APP_FLASH_SECT_LEN,   FLASH_APP },
    { 11, 0x080E0000, APP_FLASH_SECT_LEN,   FLASH_APP },
    { -1, 0,          0,        FLASH_INVALID}
};

void mpu_config(int);

void memory_protect(void);

/// Enable writing. This exercises a bug in the STM32F2 that allows writing to
/// read-only sectors of flash.
void memory_unlock(void);


/// Double sha256 hash of the bootloader.
///
/// \param hash    Buffer to be filled with hash.
///                Must be at least SHA256_DIGEST_LENGTH bytes long.
/// \param cached  Whether a cached value is acceptable.
int memory_bootloader_hash(uint8_t *hash, bool cached);

int memory_firmware_hash(uint8_t *hash);
int memory_storage_hash(uint8_t *hash, Allocation storage_location);
bool find_active_storage(Allocation *storage_location);

void memory_getDeviceSerialNo(char *str, size_t len);

extern void * _timerusr_isr;
extern void * _buttonusr_isr;
extern void * _mmhusr_isr;

#endif

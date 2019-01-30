/*
 * This file is part of the KEEPKEY project.
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



#ifndef EMULATOR
#  include <libopencm3/stm32/flash.h>
#  include <libopencm3/cm3/mpu.h>
#  include <libopencm3/cm3/nvic.h>
#  include <libopencm3/cm3/scb.h>
#  include "keepkey/board/mpudefs.h"
#else
#  include <stdio.h>
#endif

#include "trezor/crypto/sha2.h"
#include "trezor/crypto/sha3.h"


#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/keepkey_flash.h"

#include <string.h>
#include <assert.h>
#include <stdint.h>

#ifdef EMULATOR
uint8_t *emulator_flash_base = NULL;
#endif


void mpu_config(int priv_level)
{
    // Entry: 
    //          priv_level is SIG_OK for KK signed firmware (currently not used, for future priv level use)
    // Exit:
    //          Memory protection is set and enabled based on priv level
    //
    // CAUTION: It is possible to disable access to critical resources even in privileged mode. This 
    // can potentially birck device

    // Disable MPU
    (void) priv_level;

#ifndef EMULATOR
    MPU_CTRL = 0;

    // Note: later entries overwrite previous ones
    // Flash (0x08000000 - 0x080FFFFF, 1 MiB, read-only)
    MPU_RBAR = FLASH_BASE | MPU_RBAR_VALID | (0 << MPU_RBAR_REGION_LSB);
    MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_FLASH | MPU_RASR_SIZE_1MB | MPU_RASR_ATTR_AP_PRW_URO;

    // SRAM (0x20000000 - 0x2001FFFF, read-write, execute never)
    MPU_RBAR = SRAM_BASE | MPU_RBAR_VALID | (1 << MPU_RBAR_REGION_LSB);
    MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_SRAM | MPU_RASR_SIZE_128KB | MPU_RASR_ATTR_AP_PRW_URW | MPU_RASR_ATTR_XN;

    // SRAM (0x2001F800 - 0x2001FFFF, bootloader protected ram, priv read-write only, execute never, disable high subregion)
    MPU_RBAR = BLPROTECT_BASE | MPU_RBAR_VALID | (2 << MPU_RBAR_REGION_LSB);
    MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_SRAM | MPU_RASR_DIS_SUB_8 | MPU_RASR_SIZE_2KB | MPU_RASR_ATTR_AP_PRW_UNO | MPU_RASR_ATTR_XN;

    // Peripherals are not accessible by default, allow unpriv access (0x40020000 - 0x40023FFF, read-write, execute never)
    MPU_RBAR = 0x40020000 | MPU_RBAR_VALID | (3 << MPU_RBAR_REGION_LSB);
    MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_PERIPH | MPU_RASR_SIZE_16KB | MPU_RASR_ATTR_AP_PRW_URW | MPU_RASR_ATTR_XN;

    // by default, the flash controller regs are accessible in unpriv mode, apply protection
    // (0x40023C00 - 0x40023FFF, privileged read-write, unpriv no, execute never)
    MPU_RBAR = 0x40023c00 | MPU_RBAR_VALID | (4 << MPU_RBAR_REGION_LSB);
    MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_PERIPH | MPU_RASR_SIZE_1KB | MPU_RASR_ATTR_AP_PRW_UNO | MPU_RASR_ATTR_XN;

#ifdef  USART_DEBUG_ON
    // USART3 is open to unprivileged access for usart debug versions only
    // (0x40004800 - 0x40004BFF)
    MPU_RBAR = 0x40004800 | MPU_RBAR_VALID | (5 << MPU_RBAR_REGION_LSB);
    MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_PERIPH | MPU_RASR_SIZE_1KB | MPU_RASR_ATTR_AP_PRW_URW | MPU_RASR_ATTR_XN;
#else
    // If using release firmware, use this region to protect the sysconfig registers
    // (0x40013800 - 0x40013BFF, read-only, execute never)
    MPU_RBAR = 0x40013800 | MPU_RBAR_VALID | (5 << MPU_RBAR_REGION_LSB);
    MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_PERIPH | MPU_RASR_SIZE_1KB | MPU_RASR_ATTR_AP_PRO_UNO | MPU_RASR_ATTR_XN;
#endif

    // Allow access to the block from the USB FS periph up through the RNG to capture these two periphs in one region
    // (0x50000000 - 0x50080000)
    MPU_RBAR = 0x50060800 | MPU_RBAR_VALID | (6 << MPU_RBAR_REGION_LSB);
    MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_PERIPH | MPU_RASR_SIZE_512KB | MPU_RASR_ATTR_AP_PRW_URW | MPU_RASR_ATTR_XN;

    // OTP and unique ids is open to unprivileged access
    // (0x1FFF7800 - 0x1FFF7C00)
    MPU_RBAR = 0x1FFF7800 | MPU_RBAR_VALID | (7 << MPU_RBAR_REGION_LSB);
    MPU_RASR = MPU_RASR_ENABLE | MPU_RASR_ATTR_PERIPH | MPU_RASR_SIZE_1KB | MPU_RASR_ATTR_AP_PRW_URW | MPU_RASR_ATTR_XN;

    // Enable MPU and use the default system memory privileges as the background execution of the system memory map.
    MPU_CTRL = MPU_CTRL_ENABLE | MPU_CTRL_PRIVDEFENA;

    // Enable memory fault handler
    SCB_SHCSR |= SCB_SHCSR_MEMFAULTENA;

    __asm__ volatile("dsb");
    __asm__ volatile("isb");
#endif //EMULATOR

}


/*
 * memory_protect() - Set option bytes for memory protection
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void memory_protect(void)
{
#ifndef EMULATOR
    /*                     set RDP level 2                   WRP for sectors 0,5,6  */
    if((((*OPTION_BYTES_1) & 0xFFFF) == OPTION_RDP) && (((*OPTION_BYTES_2) & 0xFFFF) == OPTION_WRP))
    {
        return; // already set up correctly - bail out
    }

    flash_unlock_option_bytes();
    /*                              WRP +    RDP */

#if !defined(DEBUG_ON)  // safety check to make sure mem protect disabled in debug builds
    flash_program_option_bytes((uint32_t)OPTION_WRP << 16 | OPTION_RDP);  //RDP BLevel 2 (Irreversible)
#endif

    flash_lock_option_bytes();
#else
    printf("memory protect ON\n");
#endif
}

void memory_unlock(void) {
#ifndef EMULATOR
    // This exercises a bug in the STM32F2 that allows writing to read-only
    // sectors of flash.
    flash_unlock_option_bytes();
    
#ifdef DEBUG_ON
    // 0xFFFAAEC: remove wp from all sectors, no RDP (unless previously set to level 2 which is irreversible), 
    // disable configurable resets. Low order two bits are don't care.
    flash_program_option_bytes(0x0FFFAAEC);
#else
    // Even though level 2 is described as sticky, this chip has a proven bug related to this register so 
    // to be sure rewrite the level two value for RDP for non-debug builds.
    flash_program_option_bytes(0x0FFFCCEC);
#endif

    flash_lock_option_bytes();
#endif
}

int memory_bootloader_hash(uint8_t *hash, bool cached)
{
    static uint8_t cached_hash[SHA256_DIGEST_LENGTH];

    if(cached_hash[0] == '\0' || !cached)
    {
        sha256_Raw((const uint8_t *)FLASH_BOOT_START, FLASH_BOOT_LEN, cached_hash);
        sha256_Raw(cached_hash, SHA256_DIGEST_LENGTH, cached_hash);
    }

    memcpy(hash, cached_hash, SHA256_DIGEST_LENGTH);

    return SHA256_DIGEST_LENGTH;
}

/*
 * memory_firmware_hash() - SHA256 hash of firmware (meta and application)
 *
 * INPUT
 *     - hash: buffer to be filled with hash
 * OUTPUT
 *     none
 */
int memory_firmware_hash(uint8_t *hash)
{
#ifndef EMULATOR
    SHA256_CTX ctx;
    uint32_t codelen = *((uint32_t *)FLASH_META_CODELEN);

    if(codelen <= FLASH_APP_LEN)
    {
        sha256_Init(&ctx);
        sha256_Update(&ctx, (const uint8_t *)META_MAGIC_STR, META_MAGIC_SIZE);
        sha256_Update(&ctx, (const uint8_t *)FLASH_META_CODELEN,
                      FLASH_META_DESC_LEN - META_MAGIC_SIZE);
        sha256_Update(&ctx, (const uint8_t *)FLASH_APP_START, codelen);
        sha256_Final(&ctx, hash);
        return SHA256_DIGEST_LENGTH;
    }
    else
    {
        return 0;
    }
#else
    return 0;
#endif
}

/*
 * memory_storage_hash() - SHA256 hash of storage area
 *
 * INPUT
 *     - hash: buffer to be filled with hash
 *     - storage_location: current storage location (changes due to wear leveling)
 * OUTPUT
 *     none
 */
int memory_storage_hash(uint8_t *hash, Allocation storage_location)
{
    const uint8_t *storage_location_start;
    storage_location_start = (const uint8_t *)flash_write_helper(storage_location);

    sha256_Raw(storage_location_start, STORAGE_SECTOR_LEN, hash);
    return SHA256_DIGEST_LENGTH;
}

/*
 * find_active_storage() - Find a sector with valid data
 *
 * INPUT -
 *       - storage_location: pointer to save config data
 * OUTPUT -
 *      status
 *
 */
bool find_active_storage(Allocation *storage_location)
{
    bool ret_stat = false;
    Allocation storage_location_use;
    size_t storage_location_start;

    /* Find 1st storage sector with valid data */
    for(storage_location_use = FLASH_STORAGE1; storage_location_use <= FLASH_STORAGE3;
            storage_location_use++)
    {
        storage_location_start = flash_write_helper(storage_location_use);

        if(memcmp((void *)storage_location_start, STORAGE_MAGIC_STR, STORAGE_MAGIC_LEN) == 0)
        {
            /* Found valid data.  Load data and exit */
            *storage_location = storage_location_use;
            ret_stat = true;
            break;
        }
    }

    return(ret_stat);
}


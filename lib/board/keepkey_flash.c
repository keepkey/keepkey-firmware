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

/* === Includes ============================================================ */

#ifndef EMULATOR
#  include <libopencm3/stm32/flash.h>
#endif

#include "keepkey/board/keepkey_flash.h"

#include "keepkey/board/check_bootloader.h"

#include <string.h>
#include <stdint.h>

/* === Functions =========================================================== */

/*
 * flash_write_helper() - Helper function to locate starting address of 
 * the functional group
 * 
 * INPUT
 *     - group: functional group
 * OUTPUT
 *     starting address of functional group
 */
uint32_t flash_write_helper(Allocation group)
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
 * flash_chk_status() - Get flash operation status
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false flash operation status
 */
bool flash_chk_status(void)
{
#ifndef EMULATOR
    if(FLASH_SR & (FLASH_SR_PGAERR | FLASH_SR_PGPERR | FLASH_SR_PGSERR | FLASH_SR_WRPERR)) {
        /* Flash error detected */
        return(false);
    }else {
        /* Flash operation successful */
        return(true);
    }
#else
    return true;
#endif
}

/*
 * flash_erase_word() - Flash erase in word (32bit) size
 *
 * INPUT
 *     - group: functional group
 * OUTPUT
 *     none
 */
void flash_erase_word(Allocation group)
{
#ifndef EMULATOR
    const FlashSector* s = flash_sector_map;
    while(s->use != FLASH_INVALID)
    {
        if(s->use == group) {
            flash_erase_sector(s->sector, FLASH_CR_PROGRAM_X32);
        }
        ++s;
    }
#endif
}

/*
 * flash_erase() - Flash erase in byte size
 *
 * INPUT
 *     - group: functional group 
 * OUTPUT
 *     none
 */
void flash_erase(Allocation group)
{
#ifndef EMULATOR
    const FlashSector* s = flash_sector_map;
    while(s->use != FLASH_INVALID)
    {
        if(s->use == group) {
            flash_erase_sector(s->sector, FLASH_CR_PROGRAM_X8);
        }
        ++s;
    }
#endif
}

/*
 * flash_write_word() - Flash write in word (32bit) size
 *
 * INPUT
 *     - group: functional group
 *     - offset: flash address offset
 *     - len: length of source data
 *     - data: pointer to source data 
 * OUTPUT:
 *     true/false status of write
 */
bool flash_write_word(Allocation group, uint32_t offset, uint32_t len, uint8_t *data)
{
#ifndef EMULATOR
    bool retval = true;
    uint32_t start = flash_write_helper(group);
    uint32_t data_word[1];
    uint32_t i, align_cnt = 0;

    start += offset ;

    /* Byte writes for flash start address not long-word aligned */
    if(start % sizeof(uint32_t)) {
        align_cnt = sizeof(uint32_t) - start % sizeof(uint32_t);
        flash_program(start, data, align_cnt);
        if(flash_chk_status() == false) {
            retval = false;
            goto fww_exit;
        }
        /* Update new start address/data & len */
        start += align_cnt;
        data += align_cnt;
        len -= align_cnt;
    }

    /* Long word writes */
    for(i = 0 ; i < len/sizeof(uint32_t); i++)
    {
        memcpy(data_word, data, sizeof(uint32_t));
	    flash_program_word(start, *data_word);
	    // check flash status register for error condition
        if(flash_chk_status() == false) {
            retval = false;
            goto fww_exit;
        }
        start += sizeof(uint32_t);
        data += sizeof(uint32_t);
    }

    /* Byte write for last remaining bytes < longword */
    if(len % sizeof(uint32_t)) {
        flash_program(start, data, len % sizeof(uint32_t));
        if(flash_chk_status() == false) {
            retval = false;
        }
    }
fww_exit:
    return(retval);
#endif
    return false;
}

/*
 * flash_write() - Flash write in byte size
 *
 * INPUT : 
 *     - group: functional group
 *     - offset: flash address offset
 *     - len: length of source data
 *     - data: source data address
 * OUTPUT:
 *     true/false status of write
 */
bool flash_write(Allocation group, uint32_t offset, uint32_t len, uint8_t* data)
{
#ifndef EMULATOR
    bool retval = true;
    uint32_t start = flash_write_helper(group);
    flash_program(start + offset, data, len);
    if(flash_chk_status() == false) {
        retval = false;
    }
    return(retval);
#else
    return true;
#endif
}

/*
 * is_mfg_mode() - Is device in manufacture mode
 *
 * INPUT - 
 *      none
 * OUTPUT -
 *      none
 */
bool is_mfg_mode(void)
{
    bool ret_val = true;

#ifndef EMULATOR
    if(*(uint32_t *)OTP_MFG_ADDR == OTP_MFG_SIG)
    {
         ret_val = false;
    }
#endif

    return(ret_val);
}

/*
 * set_mfg_mode_off() - Set manufacture mode off and lock the block
 *
 * INPUT -
 *      none
 * OUTPUT - 
 *      none
 */
bool set_mfg_mode_off(void)
{
    bool ret_val = false;
    uint32_t tvar;

#ifndef EMULATOR
    /* check OTP lock state before updating */
    if(*(uint8_t *)OTP_BLK_LOCK(OTP_MFG_ADDR) == 0xFF)
    {
        flash_unlock();
        tvar = OTP_MFG_SIG; /* set manufactur'ed signature */
        flash_program(OTP_MFG_ADDR, (uint8_t *)&tvar, OTP_MFG_SIG_LEN);
        tvar = 0x00;        /* set OTP lock */
        flash_program(OTP_BLK_LOCK(OTP_MFG_ADDR), (uint8_t *)&tvar, 1);
        if(flash_chk_status()) 
        {
            ret_val = true;
        }
        flash_lock();
    }
#endif

    return(ret_val);
}

const char *flash_getModel(void) {
#ifndef EMULATOR
    if (*((uint8_t*)OTP_MODEL_ADDR) == 0xFF)
        return NULL;

    return (char*)OTP_MODEL_ADDR;
#else
    // TODO: actually make this settable in the emulator
    return "K1-14AM";
#endif
}

bool flash_setModel(const char (*model)[32]) {
#ifndef EMULATOR
    // Check OTP lock state before updating
    if (*(uint8_t*)OTP_BLK_LOCK(OTP_MODEL_ADDR) != 0xFF)
        return false;

    flash_unlock();
    flash_program(OTP_MODEL_ADDR, (uint8_t*)model, sizeof(*model));
    uint8_t lock = 0x00;
    flash_program(OTP_BLK_LOCK(OTP_MODEL_ADDR), &lock, sizeof(lock));
    bool ret = flash_chk_status();
    flash_lock();
    return ret;
#else
    return true;
#endif
}

const char *flash_programModel(void) {
    const char *ret = flash_getModel();
    if (ret)
        return ret;

    switch (get_bootloaderKind()) {
    case BLK_UNKNOWN:
        return "Unknown";
    case BLK_v1_0_0:
    case BLK_v1_0_1:
    case BLK_v1_0_2:
    case BLK_v1_0_3:
    case BLK_v1_0_3_sig:
    case BLK_v1_0_3_elf: {
#define MODEL_KK(NUMBER) \
        static const char model[32] = (NUMBER);
#include "keepkey/board/models.def"
        if (!is_mfg_mode())
            (void)flash_setModel(&model);
        return model;
    }
    case BLK_v1_0_4: {
#define MODEL_SALT(NUMBER) \
        static const char model[32] = (NUMBER);
#include "keepkey/board/models.def"
        if (!is_mfg_mode())
            (void)flash_setModel(&model);
        return model;
    }
    }

#ifdef DEBUG_ON
     __builtin_unreachable();
#else
    return "Unknown";
#endif
}

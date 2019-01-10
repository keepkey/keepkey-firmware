/*
 * Copyright (C) 2018 Keepkey
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
#   include <libopencm3/stm32/flash.h>
#else
#   include <stdint.h>
#   include <stdbool.h>
#endif

#include <stdint.h>
#include <string.h>
#include "keepkey/board/supervise.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/keepkey_flash.h"

#ifndef EMULATOR


/* Return context from user isr processing
*/
void svc_busr_return(void) {
	__asm__ __volatile__ ("svc %0" :: "i" (SVC_BUSR_RET) : "memory");
}

/* Return context from user isr processing
*/
void svc_tusr_return(void) {
	__asm__ __volatile__ ("svc %0" :: "i" (SVC_TUSR_RET) : "memory");
}

/* enable interrupts
*/
void svc_enable_interrupts(void) {
	__asm__ __volatile__ ("svc %0" :: "i" (SVC_ENA_INTR) : "memory");
}

/* Return context from user isr processing
*/
void svc_disable_interrupts(void) {
	__asm__ __volatile__ ("svc %0" :: "i" (SVC_DIS_INTR) : "memory");
}

/* Erase a flash sector.
 * @param sector sector number 0..11 
 */
void svc_flash_erase_sector(uint32_t sector) {
	_param_1 = sector;
	__asm__ __volatile__ ("svc %0" :: "i" (SVC_FLASH_ERASE) : "memory");
}

bool svc_flash_pgm_blk(uint32_t beginAddr, uint32_t data, uint32_t align) {
    _param_1 = beginAddr;
    _param_2 = data;
    _param_3 = align;
	__asm__ __volatile__ ("svc %0" :: "i" (SVC_FLASH_PGM_BLK) : "memory");
	return((bool)_param_1);
}

bool svc_flash_pgm_word(uint32_t beginAddr, uint32_t data) {
    _param_1 = beginAddr;
    _param_2 = data;
	__asm__ __volatile__ ("svc %0" :: "i" (SVC_FLASH_PGM_WORD) : "memory");
	return((bool)_param_1);
}



void svhandler_flash_erase_sector(void) {
	/* do not allow firmware to erase bootstrap or bootloader sectors */
	if ((_param_1 == FLASH_BOOTSTRAP_SECTOR) || 
		(_param_1 >= FLASH_BOOT_SECTOR_FIRST && _param_1 <= FLASH_BOOT_SECTOR_LAST)) {
		return;
	}
	// unlock the flash
	flash_clear_status_flags();
	flash_unlock();

	// erase the sector
	flash_erase_sector(_param_1, FLASH_CR_PROGRAM_X32);

	// lock the flash
	/* Wait for any write operation to complete. */
	flash_wait_for_last_operation();
	/* Disable writes to flash. */
	FLASH_CR &= ~FLASH_CR_PG;
	/* lock flash register */
	FLASH_CR |= FLASH_CR_LOCK;
	/* return flash status register */
	return;

}


void svhandler_flash_pgm_blk(void) {
	/* do not allow firmware to erase bootstrap or bootloader sectors */

	if (
		((_param_1 >= BSTRP_FLASH_SECT_START) && (_param_1 <= (BSTRP_FLASH_SECT_START+BSTRP_FLASH_SECT_LEN-1))) ||
		(((_param_1+_param_3) >= BSTRP_FLASH_SECT_START) && 
		((_param_1+_param_3) <= (BSTRP_FLASH_SECT_START+BSTRP_FLASH_SECT_LEN-1)))
	   ) {
		return;
	}

	if (
		((_param_1 >= BLDR_FLASH_SECT_START) && (_param_1 <= (BLDR_FLASH_SECT_START+2*BLDR_FLASH_SECT_LEN-1))) ||
		(((_param_1+_param_3) >= BLDR_FLASH_SECT_START) && 
		((_param_1+_param_3) <= (BLDR_FLASH_SECT_START+2*BLDR_FLASH_SECT_LEN-1)))
	   ) {
		return;
	}

	// unlock the flash
	flash_clear_status_flags();
	flash_unlock();

	// flash write
    flash_program(_param_1, (uint8_t *)_param_2, _param_3);
    if(flash_chk_status() == false) {
    	_param_1 = (uint32_t)false;
    } else {
    	_param_1 = (uint32_t)true;
    }
 
	// lock the flash
	/* Wait for any write operation to complete. */
	flash_wait_for_last_operation();
	/* Disable writes to flash. */
	FLASH_CR &= ~FLASH_CR_PG;
	/* lock flash register */
	FLASH_CR |= FLASH_CR_LOCK;
	/* return flash status register */
	return;
}



void svhandler_flash_pgm_word(void) {
	/* do not allow firmware to erase bootstrap or bootloader sectors */
	if (
		(_param_1 >= BSTRP_FLASH_SECT_START) && (_param_1 <= (BSTRP_FLASH_SECT_START+BSTRP_FLASH_SECT_LEN)) 
	   ) {
		return;
	}

	if (
		((_param_1 >= BLDR_FLASH_SECT_START) && (_param_1 <= (BLDR_FLASH_SECT_START+2*BLDR_FLASH_SECT_LEN))) 
	   ) {
		return;
	}

	// unlock the flash
	flash_clear_status_flags();
	flash_unlock();

	// flash write

    flash_program_word(_param_1, _param_2);
    if(flash_chk_status() == false) {
    	_param_1 = false;
    } else {
    	_param_1 = true;
    }
 
	// lock the flash
	/* Wait for any write operation to complete. */
	flash_wait_for_last_operation();
	/* Disable writes to flash. */
	FLASH_CR &= ~FLASH_CR_PG;
	/* lock flash register */
	FLASH_CR |= FLASH_CR_LOCK;
	/* return flash status register */
	return;
}


void svc_handler_main(uint32_t *stack) {
	uint8_t svc_number = ((uint8_t*) stack[6])[-2];
	switch (svc_number) {
	case SVC_BUSR_RET:
		svhandler_button_usr_return();
		break;
	case SVC_TUSR_RET:
		svhandler_timer_usr_return();
		break;
	case SVC_ENA_INTR:
		svhandler_enable_interrupts();
		break;
	case SVC_DIS_INTR:
		svhandler_disable_interrupts();
		break;
	case SVC_FLASH_ERASE:
		svhandler_flash_erase_sector();
		break;
	case SVC_FLASH_PGM_BLK:
		svhandler_flash_pgm_blk();
		break;
	case SVC_FLASH_PGM_WORD:
		svhandler_flash_pgm_word();
		break;
	case SVC_FIRMWARE_PRIV:
	case SVC_FIRMWARE_UNPRIV:
		svhandler_start_firmware(svc_number);
		break;
	default:
		stack[0] = 0xffffffff;
		break;
	}
}

#endif

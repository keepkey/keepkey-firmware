/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (C) 2018 Jochen Hoenicke <hoenicke@gmail.com>
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

#ifndef __SUPERVISE_H__
#define __SUPERVISE_H__

#define SVC_BUSR_RET      		1
#define SVC_TUSR_RET	  		2
#define	SVC_ENA_INTR 	 		3 
#define SVC_DIS_INTR 			4
#define SVC_FLASH_ERASE   		5
#define SVC_FLASH_PGM_BLK  		6
#define SVC_FLASH_PGM_WORD    	7
#define SVC_FIRMWARE_PRIV		8
#define SVC_FIRMWARE_UNPRIV		9	//WARNING: do not change this value unless you also change svc_firmware_unpriv in isr.s to match



#ifndef	__ASSEMBLER__


extern uint32_t _param_1;
extern uint32_t _param_2;
extern uint32_t _param_3;


void svc_busr_return(void);
void svc_tusr_return(void);
void svc_enable_interrupts(void);
void svc_disable_interrupts(void);

/// svc calls to erase and write the flash should not be done in bootloader, use direct erase and write functions

/**
 * svc_flash_erase_sector() - request to erase a flash sector
 * entry:
 *		sector is the flash sector to erase (0-11)
 * exit:
 *	    requested sector is erased if legal: note that bootstrap and bootloader sectors cannot
 *       be erased with this call.
**/
void svc_flash_erase_sector(uint32_t sector); 

/**
 * svc_flash_pgm_blk() - request to program a block of data
 * entry:
 *		beginAddr is the start address in flash
 *      data is the data to write
 *      align is the alignment
 * exit:
 *	    returns true if successful, otherwise false
**/
bool svc_flash_pgm_blk(uint32_t beginAddr, uint32_t data, uint32_t align);

/**
 * svc_flash_pgm_word() - request to program a word of data
 * entry:
 *		beginAddr is the start address in flash
 *      data is the data to write
 * exit:
 *	    returns true if successful, otherwise false
**/
bool svc_flash_pgm_word(uint32_t beginAddr, uint32_t data);


/// These are the handlers that reside in the bootloader

/**
	svhandler_flash_erase_sector() - handler to erase a sector

    on entry: 
   			 _param_1: sector to erase
	on exit:

	svc calls to erase and write the flash should not be done in bootloader, use direct erase and write functions
**/
void svhandler_flash_erase_sector(void);


void svhandler_button_usr_return(void);
void svhandler_timer_usr_return(void);
void svhandler_enable_interrupts(void);
void svhandler_disable_interrupts(void);

/**
	svhandler_flash_pgm_blk() - handler to program a block
    On entry: 
   			 _param_1 = address: uint32_t start address in flash
             _param_2 = data:    uint8_t * to data block to write
             _param_3 = length:  uint32_t length to write
	on exit:
			 _param_1 = true if write status good, otherwise false

	svc calls to erase and write the flash should not be done in bootloader, use direct erase and write functions
**/
void svhandler_flash_pgm_blk(void);

/**
   svhandler_flash_pgm_word() - handler to program a word
   On entry: 
   			 _param_1 = address: uint32_t start address in flash
             _param_2 = data:    uint32_t of word to write
	on exit:
			 _param_1 = true if write status good, otherwise false

	 svc calls to erase and write the flash should not be done in bootloader, use direct erase and write functions
*/
void svhandler_flash_pgm_word(void);

void svhandler_start_firmware(uint32_t);

#endif

#endif

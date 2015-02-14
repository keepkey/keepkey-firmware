/* START KEEPKEY LICENSE */
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
 *
 */
/* END KEEPKEY LICENSE */

#ifndef KEEPKEY_BOARD_H
#define KEEPKEY_BOARD_H

#include <keepkey_leds.h>
#include <keepkey_display.h>
#include <keepkey_button.h>
#include <layout.h>
#include <timer.h>
#include <usb_driver.h>
#include <storage.pb.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief miscellaneous board functions    
 */
/*
 storage layout:

 offset | type/length |  description
--------+-------------+-------------------------------
 0x0000 |  4 bytes    |  magic = 'stor'
 0x0004 |  12 bytes   |  uuid
 0x0010 |  25 bytes   |  uuid_str
 0x0029 |  ?          |  Storage structure
 */


/*********************  #defines *************************/
/* Specify the length of the uuid binary string */ 
#define STORAGE_UUID_LEN 12
/* Length of the uuid binary converted to readable ASCII.  */
#define STORAGE_UUID_STR_LEN ((STORAGE_UUID_LEN * 2) + 1)

/* set initial __stack_chk_guard to a value from arbitrary RAM location */
#define SSP_GUARD_VAL (*(uintptr_t *)0x2001FB10)
/***************** typedefs and enums  *******************/
/* Flash metadata structure which will contains unique identifier
   information that spans device resets.  */
typedef struct
{
    char magic[4];
    uint8_t uuid[STORAGE_UUID_LEN];
    char uuid_str[STORAGE_UUID_STR_LEN];
} Metadata;

/* Config flash overlay structure.  */
typedef struct 
{
    Metadata meta;
    Storage storage;
    Cache cache;
} ConfigFlash;

/***************** external variable declarations ********/
extern uintptr_t __stack_chk_guard; 

/***************** Function Declaration *********************/
/* Perform a soft reset of the board.  */
void board_reset(void);
void scb_reset_system(void);
/* Initial setup and configuration of board.  */
void board_init(void);

void __stack_chk_fail(void) __attribute__((noreturn));

#ifdef __cplusplus
}
#endif

#endif

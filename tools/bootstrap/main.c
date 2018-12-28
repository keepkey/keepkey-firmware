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


#include "keepkey/bootstrap/bootstrap.h"

#include "keepkey/board/memory.h"
#include "keepkey/board/keepkey_board.h"

#include <libopencm3/stm32/spi.h>
#include <libopencm3/cm3/cortex.h>


static uint32_t * const  SCB_VTOR = (uint32_t*)0xe000ed08;



/*
 * zero_out_sram() - Fill entire SRAM sector with 0
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
static void zero_out_sram(void)
{
    memset_reg(_ram_start, _ram_end, 0);
}



/*
 * set_vector_table_bootloader() - Resets the vector table to point to the
 * bootloaders's vector table.
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
static void set_vector_table_bootloader(void)
{ 
    static const uint32_t NVIC_OFFSET_FLASH = ((uint32_t)FLASH_ORIGIN);

    *SCB_VTOR = NVIC_OFFSET_FLASH | ((FLASH_BOOT_START - FLASH_ORIGIN) & (uint32_t)0x1FFFFF80);
}

/*
 * bootstrap_halt() - Bootstrap system halt
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
static void __attribute__((noreturn)) bootstrap_halt(void)
{
    for(;;); /* Loops forever */
}

/*
 * bootloader_jump() - Jump to bootloader
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
static void bootloader_jump(void)
{
    uint32_t entry_address = FLASH_BOOT_START + 4;
    uint32_t bootloader_entry_address = (uint32_t)(*(uint32_t*)(entry_address));
    bootloader_entry_t bootloader_entry = (bootloader_entry_t)bootloader_entry_address;
    bootloader_entry();
}


/*
 * main - Bootstrap main entry function
 *
 * INPUT
 *     - argc: (not used)
 *     - argv: (not used)
 * OUTPUT
 *     0 when complete
 */
int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    /* Main loop for bootloader to transition to next step */
	cm_disable_interrupts();
    zero_out_sram();
    set_vector_table_bootloader();
    bootloader_jump();
    bootstrap_halt();

    return(0); /* Should never get here */
}

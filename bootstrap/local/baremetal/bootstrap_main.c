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

//================================ INCLUDES =================================== 
//
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/spi.h>
#include <libopencm3/stm32/f2/rng.h>
#include <libopencm3/cm3/cortex.h>

#include <memory.h>
#include <keepkey_board.h>
#include <keepkey_display.h>
#include <keepkey_leds.h>
#include <keepkey_button.h>
#include <keepkey_usart.h>
#include <timer.h>
#include <layout.h>

#include <confirm_sm.h>
//#include <usb_driver.h>
//#include <usb_flash.h>
// #include <ecdsa.h>
#include <bootloader.h>
#include <rng.h>



//=============================== VARIABLES ===================================

uint32_t * const  SCB_VTOR = (uint32_t*)0xe000ed08;

//====================== PRIVATE FUNCTION DECLARATIONS ========================


//=============================== FUNCTIONS ===================================

/*
 * system_halt() - forever loop here
 *
 * INPUT - none
 * OUTPUT - none
 */
void __attribute__((noreturn)) system_halt(void)
{
    /*disable interrupts */
	cm_disable_interrupts();
    for (;;) {} // loop forever
}

/*
 * Lightweight routine to reset the vector table to point to the application's vector table.
 *
 * @param offset This must be a multiple of 0x200.  This is added to to the base address of flash
 *               in order to compute the correct base address.
 * 
 */
static void set_vector_table_offset(uint32_t offset)
{ 
    static const uint32_t NVIC_OFFSET_FLASH = ((uint32_t)FLASH_ORIGIN);

    *SCB_VTOR = NVIC_OFFSET_FLASH | (offset & (uint32_t)0x1FFFFF80);
}

/*
 * boot_jump() - jump to application address
 *
 * INPUT - Start of application address
 * OUTPUT - none
 *
 */
static void boot_jump(uint32_t addr)
{
    /*
     * Jump to one after the base app address to get past the stack pointer.  The +1 
     * is to maintain a valid thumb instruction.
     */
    uint32_t entry_addr = addr+4;
    uint32_t app_entry_addr = (uint32_t)(*(uint32_t*)(entry_addr));
    app_entry_t app_entry = (app_entry_t)app_entry_addr;
    app_entry();
}

/*
 * configure_hw() - board initialization
 *
 * INPUT - none
 * OUTPUT - none
 */
static void configure_hw()
{
    clock_scale_t clock = hse_8mhz_3v3[CLOCK_3V3_120MHZ];
    rcc_clock_setup_hse_3v3(&clock);

    rcc_periph_clock_enable(RCC_GPIOA);
    rcc_periph_clock_enable(RCC_GPIOB);
    rcc_periph_clock_enable(RCC_GPIOC);
    rcc_periph_clock_enable(RCC_OTGFS);
    rcc_periph_clock_enable(RCC_SYSCFG);
    rcc_periph_clock_enable(RCC_TIM4);
    rcc_periph_clock_enable(RCC_RNG);
    
}
/*
 * bootstrap_init() - initialize misc initialization for bootstrap
 *
 * INPUT - none
 * OUTPUT - none
 */
static void bootstrap_init(void)
{
    /* Enable random */
    reset_rng();
    timer_init();
    usart_init();
    keepkey_leds_init();
    keepkey_button_init();
    display_init();
    layout_init( display_canvas() );
}

/*
 * main - Bootstrap main entry function
 *
 * INPUT - argc (not used)
 * OUTPUT - argv (not used)
 */
int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    configure_hw();
    bootstrap_init();
    // update default stack guard value random value (-fstack_protector_all)
    __stack_chk_guard = random32(); 

    dbg_print("BootStrap");

    /* main loop for bootloader to transition to next step */
    while(1) {
	            cm_disable_interrupts();
                set_vector_table_offset(FLASH_BOOT_START - FLASH_ORIGIN);  //offset = 0x20000
                boot_jump(FLASH_BOOT_START);
        } 
    return(false);  /* should never get here */
}

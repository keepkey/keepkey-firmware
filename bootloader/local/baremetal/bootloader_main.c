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
#include <usb_driver.h>
#include <rng.h>

#include "signatures.h"
#include "usb_flash.h"
#include "bootloader_main.h"

//=============================== VARIABLES ===================================

uint32_t *const SCB_VTOR = (uint32_t *)0xe000ed08;

//====================== PRIVATE FUNCTION DECLARATIONS ========================


//=============================== FUNCTIONS ===================================

/*
 * set_vector_table_offset() - Lightweight routine to reset the vector table to point
 * to the application's vector table.
 *
 * INPUT -
 *     1. offset - This must be a multiple of 0x200.  This is added to to the base address of flash
 *     in order to compute the correct base address.
 * OUTPUT - none
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
    uint32_t entry_addr = addr + 4;
    uint32_t app_entry_addr = (uint32_t)(*(uint32_t *)(entry_addr));
    app_entry_t app_entry = (app_entry_t)app_entry_addr;
    app_entry();
}

/*
 * bootloader_init() - initialize misc initialization for bootloader
 *
 * INPUT - none
 * OUTPUT - none
 *
 */
static void bootloader_init(void)
{
    reset_rng();//
    timer_init();
    usart_init();
    keepkey_leds_init();
    keepkey_button_init();
    display_hw_init();
    layout_init(display_canvas_init());
}

/*
 * clock_init() - clock initialization
 *
 * INPUT - none
 * OUTPUT - none
 *
 */
static void clock_init(void)
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
    rcc_periph_clock_enable(RCC_CRC);
}

/*
 *  is_fw_update_mode() - Determines whether in firmware update mode or not
 *
 *  INPUT - none
 *  OUTPUT - true/false
 *
 */
static bool is_fw_update_mode(void)
{
#if DEBUG_LINK
    return true;
#else
    return keepkey_button_down();
#endif
}

/*
 *  magic_ok() - check application magic
 *
 *  INPUT - none
 *  OUTPUT - true/false
 *
 */
static bool magic_ok(void)
{
#ifndef DEBUG_ON
    bool ret_val = false;
    app_meta_td *app_meta = (app_meta_td *)FLASH_META_MAGIC;

    ret_val = (memcmp((void *)&app_meta->magic, META_MAGIC_STR,
                      META_MAGIC_SIZE) == 0) ? true : false;
    return(ret_val);
#else
    return(true);
#endif
}

/*
 *  boot() - Runs through application firmware checking, and then boots
 *
 *  INPUT - none
 *  OUTPUT - true/false
 *
 */
static bool boot(void)
{
    if(magic_ok())
    {
        /* Splash screen */
        layout_home();

        if(signatures_ok() == 0) /* Signature check failed */
        {
            delay_ms(500);

            if(!confirm_without_button_request("Unofficial Firmware",
                                               "Do you want to continue booting?"))
            {
                layout_simple_message("Boot Aborted");
                goto cancel_boot;
            }
        }

        led_func(CLR_RED_LED);
        cm_disable_interrupts();
        set_vector_table_offset(FLASH_APP_START - FLASH_ORIGIN);
        boot_jump(FLASH_APP_START);
    }
    else
    {
        layout_simple_message("Please Reinstall Firmware");
        goto cancel_boot;
    }

cancel_boot:
    return(false);
}

/*
 *  update_fw() - Firmware update mode
 *
 *  INPUT - none
 *  OUTPUT - none
 *
 */
static void update_fw(void)
{
    led_func(CLR_GREEN_LED);

    if(usb_flash_firmware())
    {
        layout_standard_notification("Firmware Update Complete",
                                     "Please disconnect and reconnect.", NOTIFICATION_UNPLUG);
        display_refresh();
    }
    else
    {
        layout_simple_message("Firmware Update Failure, Try Again");
    }
}

/*
 * main - Bootloader main entry function
 *
 * INPUT - argc (not used)
 * OUTPUT - argv (not used)
 */
int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    clock_init();
    bootloader_init();

    //TODO (GIT issue #49): Do not turn this on until We're ready to ship
    // memory_protect();

    /* Initialize stack guard with random value (-fstack_protector_all) */
    __stack_chk_guard = random32();

    led_func(SET_GREEN_LED);
    led_func(SET_RED_LED);

    dbg_print("\n\rKeepKey LLC, Copyright (C) 2015\n\r");
    dbg_print("BootLoader Version %d.%d (%s)\n\r", BOOTLOADER_MAJOR_VERSION,
              BOOTLOADER_MINOR_VERSION, __DATE__);

    if(is_fw_update_mode())
    {
        update_fw();
    }
    else
    {
        boot();
    }

#if DEBUG_LINK
    board_reset();
#else
    system_halt();  /* Loops forever */
#endif
    return(false);  /* Should never get here */
}

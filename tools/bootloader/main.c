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

#include "main.h"

#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/spi.h>
#include <libopencm3/stm32/f2/rng.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/cm3/cortex.h>


#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_button.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/keepkey_leds.h"
#include "keepkey/board/keepkey_usart.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/pubkeys.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/usb_driver.h"
#include "keepkey/bootloader/signatures.h"
#include "keepkey/bootloader/usb_flash.h"
#include "keepkey/rand/rng.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* === Private Variables =================================================== */

static uint32_t *const SCB_VTOR = (uint32_t *)0xe000ed08;

/* === Private Functions =================================================== */

/*
 * set_vector_table_application() - Resets the vector table to point to the
 * applications's vector table.
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
static void set_vector_table_application(void)
{
    static const uint32_t NVIC_OFFSET_FLASH = ((uint32_t)FLASH_ORIGIN);

    *SCB_VTOR = NVIC_OFFSET_FLASH | ((FLASH_APP_START - FLASH_ORIGIN) & (uint32_t)0x1FFFFF80);
}

/*
 * application_jump() - Jump to application
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
static void application_jump(void)
{
    extern char _confidential_start[];
    extern char _confidential_end[];
    memset_reg(_confidential_start, _confidential_end, 0);

    uint32_t entry_address = FLASH_APP_START + 4;
    uint32_t app_entry_address = (uint32_t)(*(uint32_t *)(entry_address));
    app_entry_t app_entry = (app_entry_t)app_entry_address;
    app_entry();
}

/*
 * bootloader_init() - Initialization for bootloader
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
static void bootloader_init(void)
{
    reset_rng();
    timer_init();
    usart_init();
    keepkey_leds_init();
    keepkey_button_init();
    storage_sector_init();
    display_hw_init();
    layout_init(display_canvas_init());
}

/*
 * clock_init() - Clock initialization
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
static void clock_init(void)
{
    struct rcc_clock_scale clock = rcc_hse_8mhz_3v3[RCC_CLOCK_3V3_120MHZ];
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
 *  INPUT
 *      none
 *  OUTPUT
 *      true/false whether firmware is in update mode
 *
 */
static bool is_fw_update_mode(void)
{
#if 0 // DEBUG_LINK
    return true;
#else
    return keepkey_button_down();
#endif
}

/*
 *  magic_ok() - Check application magic
 *
 *  INPUT
 *      none
 *  OUTPUT
 *      true/false if application has correct magic
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
 *  INPUT
 *      none
 *  OUTPUT
 *      true/false whether boot was successful
 *
 */
static bool boot(void)
{
    if(magic_ok())
    {
        layout_home();

        if(signatures_ok() != SIG_OK) /* Signature check failed */
        {
            delay_ms(500);

#if !MEMORY_PROTECT
            if(!confirm_without_button_request("Unofficial Firmware",
                                               "Do you want to continue booting?"))
            {
#endif
                layout_simple_message("Boot Aborted");
                goto cancel_boot;
#if !MEMORY_PROTECT
            }

            layout_home();
#endif
        }

        led_func(CLR_RED_LED);
        cm_disable_interrupts();
        set_vector_table_application();
        application_jump();
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
 *  INPUT
 *      none
 *  OUTPUT
 *      none
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

/* === Functions =========================================================== */

/*
 * main - Bootloader main entry function
 *
 * INPUT
 *     - argc: (not used)
 *     - argv: (not used)
 * OUTPUT
 *     0 when complete
 */
int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    clock_init();
    bootloader_init();

#if !defined(DEBUG_ON) && (MEMORY_PROTECT == 0)
#error "To compile release version, please set MEMORY_PROTECT flag"
#elif !defined(DEBUG_ON)
    /* Checks and sets memory protection */
    memory_protect();
#elif (MEMORY_PROTECT == 1)
#error "Can only compile release versions with MEMORY_PROTECT flag"
#endif

    /* Initialize stack guard with random value (-fstack_protector_all) */
    __stack_chk_guard = random32();

    led_func(SET_GREEN_LED);
    led_func(SET_RED_LED);

    dbg_print("\n\rKeepKey LLC, Copyright (C) 2015\n\r");
    dbg_print("BootLoader Version %d.%d.%d\n\r", BOOTLOADER_MAJOR_VERSION,
              BOOTLOADER_MINOR_VERSION, BOOTLOADER_PATCH_VERSION);

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
    shutdown(); /* Loops forever */
#endif

    return(0); /* Should never get here */
}

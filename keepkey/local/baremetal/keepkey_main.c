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

#include <stdbool.h>
#include <stdint.h>

#include <libopencm3/cm3/cortex.h>

#include <keepkey_board.h>
#include <keepkey_flash.h>
#include <layout.h>
#include <usb_driver.h>
#include <resources.h>
#include <keepkey_usart.h>
#include <rng.h>

#include "home_sm.h"
#include "storage.h"
#include "fsm.h"
#include "app_layout.h"

/* === Defines ============================================================= */
#define APP_VERSIONS "VERSION" \
                      VERSION_STR(MAJOR_VERSION)  "." \
                      VERSION_STR(MINOR_VERSION)  "." \
                      VERSION_STR(PATCH_VERSION)

/* These variables will be used by host application to read the version info */
const char *const application_version = APP_VERSIONS;

/* === Private Functions =================================================== */

/*
 * exec() - Main loop
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
static void exec(void)
{
    usb_poll();

    /* Attempt to animate should a screensaver be present */
    animate();
    display_refresh();
}

/*
 * screen_test() - Preform a screen test if device is in manufacture mode
 *
 * INPUT
 *      none
 * OUTPUT
 *      none
 *
 */
static void screen_test(void)
{
    if(is_mfg_mode())
    {
        layout_screen_test();
    }
}

/* === Functions =========================================================== */

/*
 * main() - Application main entry
 *
 * INPUT
 *     none
 * OUTPUT
 *     0 when complete
 */
int main(void)
{
    /* Init board */
    board_init();

    /* Init for safeguard against stack overflow (-fstack-protector-all) */
    __stack_chk_guard = (uintptr_t)random32();

    led_func(SET_RED_LED);
    dbg_print("Application Version %d.%d.%d\n\r", MAJOR_VERSION, MINOR_VERSION,
              PATCH_VERSION);

    /* Init storage */
    storage_init();

    /* Init protcol buffer message map and usb msg callback */
    fsm_init();

    led_func(SET_GREEN_LED);

    screen_test();

    /* Enable interrupt for timer */
    cm_enable_interrupts();

    usb_init();
    led_func(CLR_RED_LED);

    reset_idle_time();

    while(1)
    {
        delay_ms_with_callback(ONE_SEC, &exec, 1);
        increment_idle_time(ONE_SEC);
        toggle_screensaver();
    }

    return(0);
}

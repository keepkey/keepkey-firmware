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

#ifndef EMULATOR
#  include <inttypes.h>
#  include <stdbool.h>
#  include <libopencm3/cm3/cortex.h>
#  include <libopencm3/stm32/desig.h>
#endif

#include "keepkey/board/check_bootloader.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/u2f.h"
#include "keepkey/board/resources.h"
#include "keepkey/board/keepkey_usart.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/mpudefs.h"
#include "keepkey/board/pubkeys.h"
#include "keepkey/board/signatures.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/u2f.h"
#include "keepkey/rand/rng.h"
#include "trezor/crypto/rand.h"

#include <stdbool.h>
#include <stdint.h>

void mmhisr(void);

#define APP_VERSIONS "VERSION" \
                      VERSION_STR(MAJOR_VERSION)  "." \
                      VERSION_STR(MINOR_VERSION)  "." \
                      VERSION_STR(PATCH_VERSION)

/* These variables will be used by host application to read the version info */
static const char *const application_version
__attribute__((used, section("version"))) = APP_VERSIONS;

void memory_getDeviceSerialNo(char *str, size_t len) {
#if 0
    desig_get_unique_id_as_string(str, len);
#else
    // We don't want to use the Serial No. baked into the STM32 for privacy
    // reasons, so we fetch the one from storage instead:
    strlcpy(str, storage_getUuidStr(), len);
#endif
}

static void exec(void)
{
    usbPoll();

    /* Attempt to animate should a screensaver be present */
    animate();
    display_refresh();
}

int main(void)
{
    _buttonusr_isr = (void *)&buttonisr_usr;
    _timerusr_isr = (void *)&timerisr_usr;
    _mmhusr_isr = (void *)&mmhisr;

    // Legacy bootloader code will have interrupts disabled at this point. To maintain compatibility, the timer
    // and button interrupts need to be enabled and then global interrupts enabled. This is a nop in the modern
    // scheme

    int signed_firmware = signatures_ok();
#ifdef DEBUG_ON
    signed_firmware = SIG_OK;
#endif

    if (SIG_OK == signed_firmware) {
        cm_enable_interrupts();

        // Turn on memory protection for good signature. KK firmware is signed
        mpu_config(SIG_OK);

        // set thread mode to unprivileged here. This will help protect against 0days
        __asm__ volatile("msr control, %0" :: "r" (0x3));   // unpriv thread mode using psp stack
    }

    /* Init board */
    kk_board_init();

    /* Bootloader Verification */
    check_bootloader();

    /* Program the model into OTP, if we're not in screen-test mode, and it's
     * not already there
     */
    (void)flash_programModel();

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

    u2f_init(&u2f_do_register, &u2f_do_auth, &u2f_do_version);
    usbInit();
    led_func(CLR_RED_LED);

    reset_idle_time();

    if (is_mfg_mode())
        layout_screen_test();
    else if (variant_isMFR())
        layout_simple_message("keepkey.com/get-started");
    else
        layoutHomeForced();

    while (1) {
        delay_ms_with_callback(ONE_SEC, &exec, 1);
        increment_idle_time(ONE_SEC);
        toggle_screensaver();
    }

    return 0;
}

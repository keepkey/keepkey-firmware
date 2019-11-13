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

#include "keepkey/board/common.h"
#include "keepkey/board/check_bootloader.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/resources.h"
#include "keepkey/board/keepkey_usart.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/mpudefs.h"
#include "keepkey/board/pubkeys.h"
#include "keepkey/board/signatures.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng.h"
#include "trezor/crypto/rand.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

void mmhisr(void);
void u2fInit(void);

#define APP_VERSIONS "VERSION" \
                      VERSION_STR(MAJOR_VERSION)  "." \
                      VERSION_STR(MINOR_VERSION)  "." \
                      VERSION_STR(PATCH_VERSION)

/* These variables will be used by host application to read the version info */
static const char *const application_version
__attribute__((used, section("version"))) = APP_VERSIONS;

void memory_getDeviceLabel(char *str, size_t len) {
    const char *label = storage_getLabel();

    if (label && is_valid_ascii((const uint8_t*)label, strlen(label))) {
        snprintf(str, len, "KeepKey - %s", label);
    } else {
        strlcpy(str, "KeepKey", len);
    }
}

static bool canDropPrivs(void)
{
    switch (get_bootloaderKind()) {
    case BLK_v1_0_0:
    case BLK_v1_0_1:
    case BLK_v1_0_2:
    case BLK_v1_0_3:
    case BLK_v1_0_3_elf:
    case BLK_v1_0_3_sig:
    case BLK_v1_0_4:
    case BLK_UNKNOWN:
        return true;
    case BLK_v1_1_0:
        return true;
    case BLK_v2_0_0:
        return SIG_OK == signatures_ok();
    }
    __builtin_unreachable();
}

static void drop_privs(void)
{
    if (!canDropPrivs())
        return;

    // Legacy bootloader code will have interrupts disabled at this point.
    // To maintain compatibility, the timer and button interrupts need to
    // be enabled and then global interrupts enabled. This is a nop in the
    // modern scheme.
    cm_enable_interrupts();

    // Turn on memory protection for good signature. KK firmware is signed
    mpu_config(SIG_OK);

    // set thread mode to unprivileged here. This will help protect against 0days
    __asm__ volatile("msr control, %0" :: "r" (0x3));   // unpriv thread mode using psp stack
}

#ifndef DEBUG_ON
static void unknown_bootloader(void) {
    layout_warning_static("Unknown bootloader. Contact support.");
    shutdown();
}

static void update_bootloader(void) {
    review_without_button_request(
        "Update Recommended",
        "This device's bootloader has a known security issue. "
        "https://bit.ly/2jUTbnk "
        "Please update your bootloader.");
}
#endif

static void check_bootloader(void) {
    BootloaderKind kind = get_bootloaderKind();

    switch (kind) {
    case BLK_v1_0_0:
    case BLK_v1_0_1:
    case BLK_v1_0_2:
    case BLK_v1_0_3:
    case BLK_v1_0_3_elf:
    case BLK_v1_0_3_sig:
    case BLK_v1_0_4:
#ifndef DEBUG_ON
        update_bootloader();
#endif
        return;
    case BLK_UNKNOWN:
#ifndef DEBUG_ON
        unknown_bootloader();
#endif
        return;
    case BLK_v2_0_0:
    case BLK_v1_1_0:
        return;
    }

#ifdef DEBUG_ON
    __builtin_unreachable();
#else
    unknown_bootloader();
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

    /* Drop privileges */
    drop_privs();

    /* Init board */
    kk_board_init();

    /* Program the model into OTP, if we're not in screen-test mode, and it's
     * not already there
     */
    (void)flash_programModel();

    /* Init for safeguard against stack overflow (-fstack-protector-all) */
    __stack_chk_guard = (uintptr_t)random32();

    drbg_init();

    /* Bootloader Verification */
    check_bootloader();

    led_func(SET_RED_LED);
    dbg_print("Application Version %d.%d.%d\n\r", MAJOR_VERSION, MINOR_VERSION,
              PATCH_VERSION);

    /* Init storage */
    storage_init();

    /* Init protcol buffer message map and usb msg callback */
    fsm_init();

    led_func(SET_GREEN_LED);

    usbInit(storage_isInitialized() ? "keepkey.com/wallet" : "keepkey.com/get-started");
    u2fInit();
    led_func(CLR_RED_LED);

    reset_idle_time();

    if (is_mfg_mode())
        layout_screen_test();
    else if (!storage_isInitialized())
        layout_standard_notification("Welcome", "keepkey.com/get-started",
                                     NOTIFICATION_LOGO);
    else
        layoutHomeForced();

    while (1) {
        delay_ms_with_callback(ONE_SEC, &exec, 1);
        increment_idle_time(ONE_SEC);
        toggle_screensaver();
    }

    return 0;
}

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
#include <inttypes.h>
#include <stdbool.h>
#include <libopencm3/cm3/cortex.h>
#include <libopencm3/stm32/desig.h>
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
#include "hwcrypto/crypto/rand.h"

#ifdef TWO_DISP
#include "keepkey/board/ssd1351/ssd1351.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

void mmhisr(void);
void u2fInit(void);

#define APP_VERSIONS                                    \
  "VERSION" VERSION_STR(MAJOR_VERSION) "." VERSION_STR( \
      MINOR_VERSION) "." VERSION_STR(PATCH_VERSION)

/* These variables will be used by host application to read the version info */
static const char *const application_version
    __attribute__((used, section("version"))) = APP_VERSIONS;

void memory_getDeviceLabel(char *str, size_t len) {
  const char *label = storage_getLabel();

  if (label && is_valid_ascii((const uint8_t *)label, strlen(label))) {
    snprintf(str, len, "KeepKey - %s", label);
  } else {
    strlcpy(str, "KeepKey", len);
  }
}

bool inPrivilegedMode(void) {
  // Check to see if we are in priv mode. If so, return true to drop privs.
  uint32_t creg = 0xffff;
  // CONTROL register nPRIV,bit[0]: 
  //    0 Thread mode has privileged access
  //    1 Thread mode has unprivileged access. 
  // Note: In Handler mode, execution is always privileged
  fi_defense_delay(creg);  // vary access time
  __asm__ volatile(
       "mrs %0, control" : "=r" (creg));
  fi_defense_delay(creg);  // vary test time
  if (creg & 0x0001) 
    return false;          // can't drop privs
  else
    return true;

  __builtin_unreachable();
}

static void drop_privs(void) {
  if (!inPrivilegedMode()) return;

  // Legacy bootloader code will have interrupts disabled at this point.
  // To maintain compatibility, the timer and button interrupts need to
  // be enabled and then global interrupts enabled. This is a nop in the
  // modern scheme.
  cm_enable_interrupts();

  // Turn on memory protection for good signature. KK firmware is signed
  mpu_config(SIG_OK);

  // set thread mode to unprivileged here. This will help protect against 0days
  __asm__ volatile(
      "msr control, %0" ::"r"(0x3));  // unpriv thread mode using psp stack
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
    case BLK_v1_1_0:
    case BLK_v2_0_0:
    // The security issue with bootloaders 2.1.0 - 2.1.3 is just that no one
    // should actually have them -- they were internal release candidate builds.
    case BLK_v2_1_0:
    case BLK_v2_1_1:
    case BLK_v2_1_2:
    case BLK_v2_1_3:
#ifndef DEBUG_ON
      update_bootloader();
#endif
      return;
    case BLK_UNKNOWN:
#ifndef DEBUG_ON
      unknown_bootloader();
#endif
      return;
    case BLK_v2_1_4:
      return;
  }

#ifdef DEBUG_ON
  __builtin_unreachable();
#else
  unknown_bootloader();
#endif
}

static void exec(void) {
  usbPoll();

  /* Attempt to animate should a screensaver be present */
  animate();
  display_refresh();
}

int main(void) {
  _buttonusr_isr = (void *)&buttonisr_usr;
  _timerusr_isr = (void *)&timerisr_usr;
  _mmhusr_isr = (void *)&mmhisr;

  { // limit sigRet lifetime to this block
    int sigRet = SIG_FAIL;
    sigRet = signatures_ok();
    flash_collectHWEntropy(SIG_OK == sigRet);

    /* Drop privileges */
    drop_privs();

    /* Init board */
    kk_board_init();

#ifdef TWO_DISP
    SSD1351_WriteString(0, 12, "firmware", Font_7x10, SSD1351_GREEN, SSD1351_BLACK);
#endif

    /* Program the model into OTP, if we're not in screen-test mode, and it's
     * not already there
     */
    (void)flash_programModel();

    /* Init for safeguard against stack overflow (-fstack-protector-all) */
    __stack_chk_guard = (uintptr_t)random32();

    drbg_init();

    /* Bootloader Verification. Only check if valid signed firmware on-board, allow any other firmware
    to run with any bootloader. This allows unsigned release firmware to run after warning */
    if (SIG_OK == sigRet) {
      check_bootloader();
    }
  }

  led_func(SET_RED_LED);
  dbg_print("Application Version %d.%d.%d\n\r", MAJOR_VERSION, MINOR_VERSION,
            PATCH_VERSION);

  /* Init storage */
  storage_init();

  /* Init protcol buffer message map and usb msg callback */
  fsm_init();

  led_func(SET_GREEN_LED);

  usbInit("keepkey.com");

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

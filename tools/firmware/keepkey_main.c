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

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/mpudefs.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/rust.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

void mmhisr(void);

#define APP_VERSIONS                                    \
  "VERSION" VERSION_STR(MAJOR_VERSION) "." VERSION_STR( \
      MINOR_VERSION) "." VERSION_STR(PATCH_VERSION)

/* These variables will be used by host application to read the version info */
static const char *const application_version
    __attribute__((used, section("version"))) = APP_VERSIONS;

void memory_getDeviceLabel(char *str, size_t len) {
  char label[33] = { 0 };
  rust_get_label(label, sizeof(label) - 1);

  if (is_valid_ascii((const uint8_t *)label, strlen(label))) {
    snprintf(str, len, "KeepKey - %s", label);
  } else {
    memcpy(str, "KeepKey", MIN(len, sizeof("KeepKey")));
  }
}

bool inPrivilegedMode(void) {
  // Check to see if we are in priv mode.
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
  mpu_config();

  // set thread mode to unprivileged here. This will help protect against 0days
  __asm__ volatile(
      "msr control, %0" ::"r"(0x3));  // unpriv thread mode using psp stack
}

static void exec(void) {
  // usbPoll();
  rust_exec();
}

int main(void) {
  _buttonusr_isr = (void *)&buttonisr_usr;
  _timerusr_isr = (void *)&timerisr_usr;
  _mmhusr_isr = (void *)&mmhisr;

  flash_collectHWEntropy(inPrivilegedMode());

  /* Drop privileges */
  drop_privs();

  /* Init board */
  kk_board_init();

  /* Init for safeguard against stack overflow (-fstack-protector-all) */
  __stack_chk_guard = (uintptr_t)random32();

  // dbg_print("Application Version %d.%d.%d\n\r", MAJOR_VERSION, MINOR_VERSION,
  //           PATCH_VERSION);

  /* Init Rust code */
  led_func(SET_RED_LED);
  led_func(CLR_GREEN_LED);

  rust_init();

  led_func(CLR_GREEN_LED);
  led_func(CLR_RED_LED);

  // usbInit("beta.shapeshift.com");

  while (1) {
    exec();
    delay_ms(1);
  }

  return 0;
}

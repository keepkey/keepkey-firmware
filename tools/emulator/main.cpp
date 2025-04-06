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

#include "display.h"

extern "C" {
#include "keepkey/board/common.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/resources.h"
#include "keepkey/board/keepkey_usart.h"
#include "keepkey/emulator/setup.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng.h"
}

#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>

#define APP_VERSIONS                                    \
  "VERSION" VERSION_STR(MAJOR_VERSION) "." VERSION_STR( \
      MINOR_VERSION) "." VERSION_STR(PATCH_VERSION)

/* These variables will be used by host application to read the version info */
const char *const application_version = APP_VERSIONS;

static void exec(void) {
  usbPoll();
  animate();
  display_refresh();
}

extern "C" {
void fsm_init(void);
}

extern "C" {
static volatile bool interrupted = false;
static void sigintHandler(int sig_num) {
  signal(SIGINT, sigintHandler);
  printf("Quitting...\n");
  fflush(stdout);
  exit(0);
}
}

int main(void) {
  setup();
  flash_collectHWEntropy(false);
  kk_board_init();
  drbg_init();

  led_func(SET_RED_LED);
  dbg_print("Application Version %d.%d.%d\n", MAJOR_VERSION, MINOR_VERSION,
            PATCH_VERSION);

  storage_init();

  fsm_init();

  led_func(SET_GREEN_LED);

  usbInit("keepkey.com");
  led_func(CLR_RED_LED);

  reset_idle_time();

  layoutHomeForced();

  signal(SIGINT, sigintHandler);

  while (1) {
    delay_ms_with_callback(ONE_SEC, &exec, 1);
    increment_idle_time(ONE_SEC);
    toggle_screensaver();
  }

  return 0;
}

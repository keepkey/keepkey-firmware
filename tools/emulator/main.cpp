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
#include "keepkey/board/usb.h"
#include "keepkey/emulator/setup.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng.h"
}

#include <stdbool.h>
#include <stdint.h>
#include <signal.h>

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

  led_func(SET_RED_LED);
  rust_init();

  led_func(SET_GREEN_LED);

  usbInit("beta.shapeshift.com");
  led_func(CLR_RED_LED);

  signal(SIGINT, sigintHandler);

  while (1) {
    exec();
    delay_ms(1);
  }

  return 0;
}

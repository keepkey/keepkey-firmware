/*
 * This file is part of the KEEPKEY project
 *
 * Copyright (C) 2018 KEEPKEY
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
#include <libopencm3/stm32/flash.h>
#include <libopencm3/stm32/timer.h>
#ifdef DEV_DEBUG
#include <libopencm3/stm32/f4/nvic.h>
#else
#include <libopencm3/stm32/f2/nvic.h>
#endif
#else // EMULATOR
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#endif

#include "keepkey/board/supervise.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/layout.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_ERRMSG 80

void mmhisr(void) {
#ifndef EMULATOR
#ifdef DEBUG_ON
  static char errval[MAX_ERRMSG];
  uint32_t mmfar = (uint32_t)_param_1;
  uint32_t pc = (uint32_t)_param_2;
  snprintf(errval, MAX_ERRMSG, "addr: 0x%08" PRIx32 " pc: 0x%08" PRIx32, mmfar,
           pc);
  layout_standard_notification("Memory Fault Detected", errval,
                               NOTIFICATION_UNPLUG);
#else
  layout_standard_notification("Memory Fault Detected",
                               "Please unplug your device!",
                               NOTIFICATION_UNPLUG);
#endif
  display_refresh();
  for (;;) {
  }
#else
  abort();
#endif
}

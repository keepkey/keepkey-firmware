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
#   include <libopencm3/stm32/flash.h>
#   include <libopencm3/stm32/timer.h>
#   include <libopencm3/stm32/f2/nvic.h>
#else
#   include <stdint.h>
#   include <stdbool.h>
#endif

#include "keepkey/board/supervise.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/layout.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>

// handle memory protection faults here

#define MAX_ERRMSG 40

#ifdef 	DEBUG_ON
static char errval[MAX_ERRMSG];
#endif


void mmhisr(void) {
#if !defined(EMULATOR) && defined(DEBUG_ON)
    uint32_t mmfar = (uint32_t)_param_1;
    snprintf(errval, MAX_ERRMSG, "MMFAR: %lx", mmfar);
    layout_standard_notification("MPU handler", errval, NOTIFICATION_UNPLUG);
    display_refresh();
#endif
    for (;;) {}
}

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

#ifndef KEEPKEY_USART_H
#define KEEPKEY_USART_H


#include <stdarg.h>

#include "keepkey_leds.h"
#include "keepkey_display.h"
#include "keepkey_button.h"

#include "timer.h"


#define SMALL_DEBUG_BUF     32
#define MEDIUM_DEBUG_BUF    64
#define LARGE_DEBUG_BUF     128


#ifndef EMULATOR
void dbg_print(const char *pStr, ...) __attribute__((format(printf,1,2)));
#else
#  define dbg_print(FMT, ...) do { printf(FMT, ## __VA_ARGS__); } while(0)
#endif

void usart_init(void);

#endif

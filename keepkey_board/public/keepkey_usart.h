/* START KEEPKEY LICENSE */
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
 *
 */
/* END KEEPKEY LICENSE */

#ifndef KEEPKEY_USART_H
#define KEEPKEY_USART_H

#include <keepkey_leds.h>
#include <keepkey_display.h>
#include <keepkey_button.h>
#include <layout.h>
#include <timer.h>
#include <stdarg.h>

#define SMALL_DEBUG_BUF     32
#define MEDIUM_DEBUG_BUF    64
#define LARGE_DEBUG_BUF     128

#ifdef __cplusplus
extern "C" {
#endif

bool dbg_print(char *pStr, ...); /*  print to debug console */
void usart_init(void); /* Initialize usart3 for debug port */

#ifdef __cplusplus
}
#endif

#endif

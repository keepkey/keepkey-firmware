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

#ifndef KEEPKEY_LEDS_H
#define KEEPKEY_LEDS_H


#include <stdint.h>

#include "canvas.h"


typedef enum {
    CLR_GREEN_LED,
    SET_GREEN_LED,
    TGL_GREEN_LED,
    CLR_RED_LED,
    SET_RED_LED,
    TGL_RED_LED
} LedAction;


void keepkey_leds_init( void);
void led_func(LedAction act);

#endif


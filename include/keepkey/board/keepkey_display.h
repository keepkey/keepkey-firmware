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

#ifndef KEEPKEY_DISPLAY_H
#define KEEPKEY_DISPLAY_H


#include "canvas.h"


#define START_COL ((uint8_t)0x1C)
#define START_ROW ((uint8_t)0x00)

#define KEEPKEY_DISPLAY_HEIGHT  64
#define KEEPKEY_DISPLAY_WIDTH   256

#define DEFAULT_DISPLAY_BRIGHTNESS  100 /* Percent */


void display_hw_init(void);
Canvas *display_canvas_init(void);
Canvas *display_canvas(void);
void display_refresh(void);
void display_set_brightness(int percentage);
void display_turn_on(void);
void display_turn_off(void);

typedef void (*DumpDisplayCallback)(const uint8_t*);
void display_set_dump_callback(DumpDisplayCallback d);

#endif

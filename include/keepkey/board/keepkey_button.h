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

#ifndef KEEPKEY_BUTTON_H
#define KEEPKEY_BUTTON_H


#include <stdint.h>

#include "canvas.h"


typedef void (*Handler)(void* context);



/** kk_keepkey_button_init() - Initialize push botton interrupt registers
 * and variables
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 **/
void kk_keepkey_button_init(void);

void keepkey_button_init(void);
void keepkey_button_set_on_press_handler( Handler handler, void* context);
void keepkey_button_set_on_release_handler( Handler handler, void* context);
bool keepkey_button_down(void);
bool keepkey_button_up(void);

/**
 * buttonisr_usr() - user interrupt service routine for push button external interrupt
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 **/
void buttonisr_usr(void);

#endif
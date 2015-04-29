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

//============================= CONDITIONALS ==================================


#ifndef keepkey_display_H
#define keepkey_display_H

#ifdef __cplusplus
extern "C" {
#endif

#include "canvas.h"

/**************  #defines *******************************/
#define KEEPKEY_DISPLAY_HEIGHT  64
#define KEEPKEY_DISPLAY_WIDTH   256

#define DEFAULT_DISPLAY_BRIGHTNESS  100 // percent

/**********************  Function Declarations ***********************/
void display_hw_init(void);
Canvas *display_canvas_init(void);
Canvas *display_canvas(void);
void display_refresh(void);
void display_set_brightness(int percentage);
void display_turn_on(void);
void display_turn_off(void);


#ifdef __cplusplus
}
#endif

#endif // keepkey_display_H


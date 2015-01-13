/* START KEEPKEY LICENSE */
/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2014 KeepKey LLC
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

#ifndef draw_H
#define draw_H

#ifdef __cplusplus
extern "C" {
#endif


//=============================== INCLUDES ====================================


#include <stddef.h>
#include <stdbool.h>
#include "canvas.h"
#include "font.h"
#include "resources.h"


//====================== CONSTANTS, TYPES, AND MACROS =========================


typedef struct
{
    uint8_t color;
    int     x;
    int     y;

} DrawableParams;

typedef struct
{
    DrawableParams  base;
    int             height;
    int             width;
} BoxDrawableParams;

typedef struct
{
    DrawableParams  		base;
    const ImageAnimation* 	img_animation;
} AnimationImageDrawableParams;


//=============================== VARIABLES ===================================


//=============================== FUNCTIONS ===================================


//-----------------------------------------------------------------------------
/// Draw a character on the display.
///
//-----------------------------------------------------------------------------
bool draw_char(Canvas* canvas, Font* font, char c, DrawableParams* params);


//-----------------------------------------------------------------------------
/// Draw a string on the display.
///
//-----------------------------------------------------------------------------
bool draw_string(Canvas* canvas, const Font* font, const char* c, DrawableParams* p, int width,
		int line_height);


//-----------------------------------------------------------------------------
/// Draw a box on the display.
///
//-----------------------------------------------------------------------------
bool draw_box(Canvas* canvas, BoxDrawableParams*  params);


//-----------------------------------------------------------------------------
/// Draw a bitmap on the display using RLE
///
//-----------------------------------------------------------------------------
bool draw_bitmap_mono_rle(Canvas* canvas, DrawableParams* p, const Image *img);


#ifdef __cplusplus
}
#endif

#endif // draw_H


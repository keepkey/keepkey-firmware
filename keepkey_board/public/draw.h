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

#ifndef draw_H
#define draw_H

#ifdef __cplusplus
extern "C" {
#endif


#include <stddef.h>
#include <stdbool.h>
#include "canvas.h"
#include "font.h"
#include "resources.h"


/***************** typedefs and enums  *******************/
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


/******************* Function Declarations ******************/
bool draw_char_with_shift(Canvas* canvas, DrawableParams* p,
		int* x_shift, int* y_shift, const CharacterImage* img);
void draw_string(Canvas* canvas, const Font* font, const char* c, DrawableParams* p, int width,
		int line_height);
void draw_char(Canvas *canvas, const Font *font, char c, DrawableParams *p);
void draw_box(Canvas* canvas, BoxDrawableParams*  params);
void draw_box_simple(Canvas *canvas, uint8_t color, int x, int y, int width, int height);
bool draw_bitmap_mono_rle(Canvas* canvas, DrawableParams* p, const Image *img);


#ifdef __cplusplus
}
#endif

#endif // draw_H


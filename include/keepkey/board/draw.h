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

#ifndef DRAW_H
#define DRAW_H


#include <stddef.h>
#include <stdbool.h>

#include "canvas.h"
#include "font.h"
#include "resources.h"
#include "keepkey/board/variant.h"


typedef struct
{
    uint8_t color;
    uint16_t     x;
    uint16_t     y;

} DrawableParams;

typedef struct
{
    DrawableParams  base;
    uint16_t           height;
    uint16_t             width;
} BoxDrawableParams;


bool draw_char_with_shift(Canvas *canvas, DrawableParams *p,
                          uint16_t *x_shift, uint16_t *y_shift, const CharacterImage *img);
void draw_string(Canvas *canvas, const Font *font, const char *c, DrawableParams *p,
                 uint16_t width,
                 uint16_t line_height);
void draw_char(Canvas *canvas, const Font *font, char c, DrawableParams *p);
void draw_char_simple(Canvas *canvas, const Font *font, char c, uint8_t color, uint16_t x,
                      uint16_t y);
void draw_box(Canvas *canvas, BoxDrawableParams  *params);
void draw_box_simple(Canvas *canvas, uint8_t color, uint16_t x, uint16_t y, uint16_t width, uint16_t height);
bool draw_bitmap_mono_rle(Canvas *canvas, const AnimationFrame *frame, bool erase);

#endif


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

typedef struct {
  uint8_t color;
  uint16_t x;
  uint16_t y;

} DrawableParams;

typedef struct {
  DrawableParams base;
  uint16_t height;
  uint16_t width;
} BoxDrawableParams;

bool draw_char_with_shift(Canvas* canvas, DrawableParams* p, uint16_t* x_shift,
                          uint16_t* y_shift, const CharacterImage* img);
void draw_string(Canvas* canvas, const Font* font, const char* str_write,
                 const DrawableParams* p, uint16_t width, uint16_t line_height);
/// Run draw_string()'s placement without writing pixels.
///
/// Returns true iff every character of \a str_write was placed. This is the
/// renderer reporting on itself: it shares draw_string()'s loop and its
/// per-glyph fit test rather than modelling them, so a caller measuring with
/// this function and then drawing with draw_string() cannot be told one thing
/// and shown another.
bool draw_string_fits(Canvas* canvas, const Font* font, const char* str_write,
                      const DrawableParams* p, uint16_t width,
                      uint16_t line_height);
void draw_char(Canvas* canvas, const Font* font, char c, DrawableParams* p);
void draw_char_simple(Canvas* canvas, const Font* font, char c, uint8_t color,
                      uint16_t x, uint16_t y);
void draw_box(Canvas* canvas, BoxDrawableParams* p);
void draw_box_simple(Canvas* canvas, uint8_t color, uint16_t x, uint16_t y,
                     uint16_t width, uint16_t height);
/*
 * draw_bitmap_mono_rle_valid() - Validate an RLE stream against a geometry.
 *
 * Pure and side-effect-free: decodes nothing, writes nothing, touches no
 * canvas. Returns true iff the stream is EXACTLY well-formed for a w*h image:
 *   - every packet count is valid (never 0, never 0x80/-128 — the decoder's
 *     counter is int8_t and cannot represent a 128 literal),
 *   - no run straddles the end of the image,
 *   - exactly w*h pixels are produced, and
 *   - the whole input is consumed (no trailing packets).
 *
 * The drawing path is lenient by construction (it stops once the canvas is
 * full), so callers that accept host-supplied streams MUST validate here at
 * the trust boundary rather than infer validity from a successful draw.
 *
 * INPUT
 *     - data: RLE stream
 *     - length: stream length in bytes
 *     - w, h: target image geometry
 * OUTPUT
 *     true iff the stream decodes exactly to w*h pixels
 */
bool draw_bitmap_mono_rle_valid(const uint8_t* data, uint32_t length,
                                uint16_t w, uint16_t h);

bool draw_bitmap_mono_rle(Canvas* canvas, const AnimationFrame* frame,
                          bool erase);

#endif

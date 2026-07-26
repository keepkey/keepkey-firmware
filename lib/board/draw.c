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

#include "keepkey/board/draw.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/font.h"
#include "keepkey/board/resources.h"
#include "keepkey/firmware/fsm.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>

#pragma GCC push_options
#pragma GCC optimize("-O3")

/*
 * draw_char_with_shift() - Draw image on display with left/top margins
 *
 * INPUT
 *     - canvas: canvas
 *     - p: pointer to Margins and text color
 *     - x_shift: left margin
 *     - y_shift: top margin
 *     - img: pointer to image drawn on the screen
 * OUTPUT
 *      true/false whether image was drawn
 */
bool draw_char_with_shift(Canvas* canvas, DrawableParams* p, uint16_t* x_shift,
                          uint16_t* y_shift, const CharacterImage* img) {
  bool ret_stat = false;

  uint16_t start_index = (p->y * canvas->width) + p->x;
  /* Check start_index, p->x, p->y are within bounds */
  if (start_index >= (KEEPKEY_DISPLAY_HEIGHT * KEEPKEY_DISPLAY_WIDTH)) {
    return false;
  }
  uint8_t* canvas_pixel = &canvas->buffer[start_index];
  const uint8_t* canvas_end = &canvas->buffer[canvas->width * canvas->height];

  /* Check that this was a character that we have in the font */
  if (img != NULL) {
    /* Check that it's within bounds. */
    if (((img->width + p->x) <= canvas->width) &&
        ((img->height + p->y) <= canvas->height)) {
      const uint8_t* img_pixel = &img->data[0];

      int y;

      for (y = 0; y < img->height; y++) {
        int x;

        for (x = 0; x < img->width; x++) {
          if (canvas_pixel >= canvas_end) {
            return false;  // defensive bounds check
          }
          *canvas_pixel = (*img_pixel == 0x00) ? p->color : *canvas_pixel;
          canvas_pixel++;
          img_pixel++;
        }

        canvas_pixel += (canvas->width - img->width);
      }

      if (x_shift != NULL) {
        *x_shift += img->width;
      }

      if (y_shift != NULL) {
        *y_shift += img->height;
      }

      ret_stat = true;
    }
  }

  canvas->dirty = true;

  return (ret_stat);
}

/*
 * draw_string() - Draw string with provided font
 *
 * INPUT
 *     - canvas: canvas
 *     - font: pointer to font size
 *     - str_write: pointer to string to shown on display
 *     - p: pointer to Margins and text color
 *     - width: row width allocated for drawing
 *     - line_height: offset from top of screen
 * OUTPUT
 *     none
 */
void draw_string(Canvas* canvas, const Font* font, const char* str_write,
                 const DrawableParams* p, uint16_t width,
                 uint16_t line_height) {
  uint16_t sepPixels =
      0;  // font char separation pixels for large font (pin font)

  if (!canvas) {
    return;
  }

  if (font == get_pin_font()) {
    sepPixels = 2;
  }

  bool have_space = true;
  uint16_t x_offset = 0;
  DrawableParams char_params = *p;

  while (*str_write && have_space) {
    const CharacterImage* img = font_get_char(font, *str_write);
    uint16_t word_width = img->width;
    const char* next_c = str_write + 1;

    /* Allow line breaks */
    if (*str_write == '\n') {
      char_params.y += line_height;
      x_offset = 0;
      str_write++;
      continue;
    }

    /*
     * Calculate the next word width while
     * removing spacings at beginning of lines
     */
    if (*str_write == ' ') {
      while (*next_c && *next_c != ' ' && *next_c != '\n') {
        word_width += font_get_char(font, *next_c)->width;
        next_c++;
      }
    }

    /* Determine if we need a line break */
    if ((width != 0) && (width <= canvas->width) &&
        (x_offset + word_width > width)) {
      char_params.y += line_height;
      x_offset = 0;
    }

    /* Remove spaces from beginning of of line */
    if (x_offset == 0 && *str_write == ' ') {
      str_write++;
      continue;
    }

    /* Draw Character */
    x_offset += sepPixels;
    char_params.x = x_offset + p->x;
    have_space =
        draw_char_with_shift(canvas, &char_params, &x_offset, NULL, img);
    str_write++;
  }

  canvas->dirty = true;
}

/*
 * draw_char() - Draw a single character to the display
 *
 * INPUT
 *     - canvas: canvas
 *     - font: font to use for drawing
 *     - c: character to draw
 *     - p: loccation of character placement
 * OUTPUT
 *     none
 */
void draw_char(Canvas* canvas, const Font* font, char c, DrawableParams* p) {
  const CharacterImage* img = font_get_char(font, c);
  uint16_t x_offset = 0;

  /* Draw Character */
  draw_char_with_shift(canvas, p, &x_offset, NULL, img);

  canvas->dirty = true;
}

/*
 * draw_char_simple() - Draw a single character to the display
 * without having to create box param object
 *
 * INPUT
 *     - canvas: canvas
 *     - font: font to use for drawing
 *     - c: character to draw
 *     - color: color of character
 *     - x: x position
 *     - y: y position
 * OUTPUT
 *     none
 */
void draw_char_simple(Canvas* canvas, const Font* font, char c, uint8_t color,
                      uint16_t x, uint16_t y) {
  DrawableParams p;
  p.color = color;
  p.x = x;
  p.y = y;

  draw_char(canvas, font, c, &p);
}

/*
 * draw_box() - Draw box on display
 *
 * INPUT
 *     - canvas: canvas
 *     - p: pointer to Margins and text color
 * OUTPUT
 *     none
 */
void draw_box(Canvas* canvas, BoxDrawableParams* p) {
  uint16_t start_row = p->base.y;
  uint16_t end_row = start_row + p->height;
  end_row = (end_row >= canvas->height) ? canvas->height - 1 : end_row;

  uint16_t start_col = p->base.x;
  uint16_t end_col = p->base.x + p->width;
  end_col = (end_col >= canvas->width) ? canvas->width - 1 : end_col;

  uint16_t start_index = (start_row * canvas->width) + start_col;
  uint8_t* canvas_pixel = &canvas->buffer[start_index];
  const uint8_t* canvas_end = &canvas->buffer[canvas->width * canvas->height];

  uint16_t height = end_row - start_row;
  uint16_t width = end_col - start_col;

  for (uint16_t y = 0; y < height; y++) {
    for (uint16_t x = 0; x < width; x++) {
      if (canvas_pixel >= canvas_end) {
        return;  // defensive bounds check
      }
      *canvas_pixel = p->base.color;
      canvas_pixel++;
    }

    canvas_pixel += (canvas->width - width);
  }

  canvas->dirty = true;
}

/*
 * draw_box_simple() - Draw box without having to create box param object
 *
 * INPUT
 *     canvas: canvas
 *     color: color of box
 *     x: x position
 *     y: y position
 *     width: width of box
 *     height: height of box
 * OUTPUT
 *     none
 */
void draw_box_simple(Canvas* canvas, uint8_t color, uint16_t x, uint16_t y,
                     uint16_t width, uint16_t height) {
  BoxDrawableParams box_params = {{color, x, y}, height, width};
  draw_box(canvas, &box_params);
}

/*
 * draw_bitmap_mono_rle() - Draw image
 *
 * INPUT
 *     - canvas: canvas
 *     - frame: pointer to animation frame
 * OUTPUT
 *     true/false whether image was drawn
 */
/*
 * draw_bitmap_mono_rle_valid() - see draw.h. Pure walk of the RLE grammar;
 * writes nothing. The drawing path below stops as soon as the canvas is full,
 * so it cannot tell a well-formed stream from one whose last run straddles the
 * image or that carries trailing packets. Host-supplied icons must be checked
 * here, at the trust boundary, before they are shown or cached for a session.
 */
bool draw_bitmap_mono_rle_valid(const uint8_t* data, uint32_t length,
                                uint16_t w, uint16_t h) {
  if (!data || w == 0 || h == 0) {
    return false;
  }

  const uint32_t pixels = (uint32_t)w * (uint32_t)h;
  uint32_t emitted = 0;
  uint32_t i = 0;

  while (emitted < pixels) {
    if (i >= length) {
      return false; /* ran out of input mid-image */
    }
    const uint8_t raw = data[i];
    if (raw == 0x80u || raw == 0u) {
      return false; /* undecodable (int8_t counter) / not a packet */
    }
    i++;

    uint32_t run;
    if (raw > 127u) {
      run = (uint32_t)(256u - raw); /* LITERAL: 1..127 distinct values */
      if (i + run > length) {
        return false; /* literal body truncated */
      }
      i += run;
    } else {
      run = raw; /* RUN: 1..127 copies of one value */
      if (i >= length) {
        return false; /* missing the run's value byte */
      }
      i++;
    }

    if (emitted + run > pixels) {
      return false; /* run straddles the end of the image */
    }
    emitted += run;
  }

  /* Exactly filled, and nothing left over. */
  return emitted == pixels && i == length;
}

bool draw_bitmap_mono_rle(Canvas* canvas, const AnimationFrame* frame,
                          bool erase) {
  if (!frame || !canvas) {
    return false;
  }

  const Image* img = frame->image;
  const uint8_t color = erase ? 0x0 : frame->color;

  /* Check that image will fit in bounds */
  if (((img->w + frame->x) > canvas->width) ||
      ((img->h + frame->y) > canvas->height)) {
    return false;
  }

  /* Validate the whole stream up front. The loop below fills the canvas and
   * stops, so on its own it cannot reject a final run that straddles the image
   * or trailing packets past the last pixel — it would draw and report success.
   * Checking first makes the return value mean "this stream is well-formed AND
   * was drawn", which is what callers gating on host-supplied icons need.
   * (Verified: every bundled image stream terminates exactly.) */
  if (!draw_bitmap_mono_rle_valid(img->data, img->length, img->w, img->h)) {
    return false;
  }

  int8_t sequence = 0;
  int8_t nonsequence = 0;
  uint32_t pixel_index = 0;

  for (int y0 = 0; y0 < img->h; y0++) {
    for (int x0 = 0; x0 < img->w; x0++) {
      if (pixel_index >= img->length) {
        return false;  // defensive bounds check
      }

      // sequence > 0 implies the next x pixels are the same
      // sequence < 0 implies the next -x pixels are all different
      if ((sequence == 0) && (nonsequence == 0)) {
        /* Read the packet count. 0x80 (-128) is rejected: `nonsequence` below
         * is int8_t, so -(-128) = 128 does not fit and wraps back to -128,
         * breaking the `nonsequence > 0` invariant. Under NDEBUG the assert is
         * compiled out and we would decode with a negative counter
         * (signed-overflow UB). 0 is likewise not a valid packet: it leaves
         * both counters at zero and breaks the same invariant. A host-supplied
         * icon reaches here, so fail closed rather than trust the encoder. */
        const uint8_t raw = img->data[pixel_index];
        if (raw == 0x80u || raw == 0u) {
          return false;
        }
        pixel_index++;

        /* Explicit two's-complement read. Narrowing a uint8_t > 127 straight
         * into an int8_t is implementation-defined, so spell the conversion
         * out: 1..127 stay positive (RUN), 129..255 become -127..-1 (LITERAL).
         */
        if (raw > 127u) {
          nonsequence = (int8_t)((int)raw - 256); /* -127..-1 */
          nonsequence = (int8_t)(-nonsequence);   /* 1..127, fits int8_t */
          sequence = 0;
        } else {
          sequence = (int8_t)raw; /* 1..127 */
        }
      }

      if (pixel_index >= img->length) {
        return false;  // defensive bounds check
      }

      const uint32_t canvas_index =
          ((frame->y + y0) * canvas->width) + frame->x + x0;
      canvas->buffer[canvas_index] =
          (uint8_t)((int)img->data[pixel_index] * color / 100);

      if (sequence > 0) {
        sequence--;
        if (sequence == 0) {
          pixel_index++;
        }
      } else {
        assert(nonsequence > 0);
        pixel_index++;
        nonsequence--;
      }
    }
  }

  canvas->dirty = true;
  return true;
}
#pragma GCC pop_options

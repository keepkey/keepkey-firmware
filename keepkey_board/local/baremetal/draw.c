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

/* === Includes ============================================================ */

#include <stddef.h>

#include "draw.h"
#include "keepkey_display.h"
#include "font.h"
#include "resources.h"

/* === Functions =========================================================== */

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
bool draw_char_with_shift(Canvas *canvas, DrawableParams *p,
                          uint16_t *x_shift, uint16_t *y_shift, const CharacterImage *img)
{
    bool ret_stat = false;

    uint16_t start_index = (p->y * canvas->width) + p->x;
    /* Check start_index, p->x, p->y are within bounds */
    if (start_index >= (KEEPKEY_DISPLAY_HEIGHT * KEEPKEY_DISPLAY_WIDTH)){
        return false;
    }
    uint8_t *canvas_pixel = &canvas->buffer[ start_index ];
    uint8_t *canvas_end = &canvas->buffer[canvas->width * canvas->height];

    /* Check that this was a character that we have in the font */
    if(img != NULL)
    {
        /* Check that it's within bounds. */
        if(((img->width + p->x) <= canvas->width) &&
                ((img->height + p->y) <= canvas->height))
        {
            const uint8_t *img_pixel = &img->data[ 0 ];

            int y;

            for(y = 0; y < img->height; y++)
            {
                int x;

                for(x = 0; x < img->width; x++)
                {
                    if (canvas_pixel >= canvas_end){
                        return false; // defensive bounds check
                    }
                    *canvas_pixel = (*img_pixel == 0x00) ? p->color : *canvas_pixel;
                    canvas_pixel++;
                    img_pixel++;
                }

                canvas_pixel += (canvas->width - img->width);
            }

            if(x_shift != NULL)
            {
                *x_shift += img->width;
            }

            if(y_shift != NULL)
            {
                *y_shift += img->height;
            }

            ret_stat = true;
        }
    }

    canvas->dirty = true;

    return(ret_stat);
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
void draw_string(Canvas *canvas, const Font *font, const char *str_write,
                 DrawableParams *p, uint16_t width, uint16_t line_height)
{
    bool have_space = true;
    uint16_t x_offset = 0;
    DrawableParams char_params = *p;

    while(*str_write && have_space)
    {
        const CharacterImage *img = font_get_char(font, *str_write);
        uint16_t word_width = img->width;
        char *next_c = (char *)str_write + 1;

        /* Allow line breaks */
        if(*str_write == '\n')
        {
            char_params.y += line_height;
            x_offset = 0;
            str_write++;
            continue;
        }

        /*
         * Calculate the next word width while
         * removing spacings at beginning of lines
         */
        if(*str_write == ' ')
        {

            while(*next_c && *next_c != ' ' && *next_c != '\n')
            {
                word_width += font_get_char(font, *next_c)->width;
                next_c++;
            }
        }

        /* Determine if we need a line break */
        if((width != 0) && (width <= canvas->width) && (x_offset + word_width > width))
        {
            char_params.y += line_height;
            x_offset = 0;
        }

        /* Remove spaces from beginning of of line */
        if(x_offset == 0 && *str_write == ' ')
        {
            str_write++;
            continue;
        }

        /* Draw Character */
        char_params.x = x_offset + p->x;
        have_space = draw_char_with_shift(canvas, &char_params, &x_offset, NULL, img);
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
void draw_char(Canvas *canvas, const Font *font, char c, DrawableParams *p)
{
    const CharacterImage *img = font_get_char(font, c);
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
void draw_char_simple(Canvas *canvas, const Font *font, char c, uint8_t color, uint16_t x,
                      uint16_t y)
{
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
void draw_box(Canvas *canvas, BoxDrawableParams *p)
{
    uint16_t start_row = p->base.y;
    uint16_t end_row = start_row + p->height;
    end_row = (end_row >= canvas->height) ? canvas->height - 1 : end_row;

    uint16_t start_col = p->base.x;
    uint16_t end_col = p->base.x + p->width;
    end_col = (end_col >= canvas->width) ? canvas->width - 1 : end_col;

    uint16_t start_index = (start_row * canvas->width) + start_col;
    uint8_t *canvas_pixel = &canvas->buffer[ start_index ];
    uint8_t *canvas_end = &canvas->buffer[canvas->width * canvas->height];

    uint16_t height = end_row - start_row;
    uint16_t width = end_col - start_col;



    for(uint16_t y = 0; y < height; y++)
    {
        for(uint16_t x = 0; x < width; x++)
        {
            if (canvas_pixel >= canvas_end){
                return; // defensive bounds check
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
void draw_box_simple(Canvas *canvas, uint8_t color, uint16_t x, uint16_t y, uint16_t width, uint16_t height)
{
    BoxDrawableParams box_params = {{color, x, y}, height, width};
    draw_box(canvas, &box_params);
}

/*
 * draw_bitmap_mono_rle() - Draw image
 *
 * INPUT
 *     - canvas: canvas
 *     - p: pointer to Margins and text color
 *     - img: pointer to image drawn on the screen
 * OUTPUT
 *     true/false whether image was drawn
 */
bool draw_bitmap_mono_rle(Canvas *canvas, DrawableParams *p, const Image *img)
{
    bool ret_stat = false;
    int x0, y0;
    int8_t sequence = 0;
    int8_t nonsequence = 0;
    static uint8_t image_data[KEEPKEY_DISPLAY_WIDTH * KEEPKEY_DISPLAY_HEIGHT];

    int start_index = (p->y * canvas->width) + p->x;
    uint8_t *canvas_pixel = &canvas->buffer[ start_index ];


    /* Get image data */
    img->get_image_data(image_data);

    /* Check that image will fit in bounds */
    if(((img->width + p->x) <= canvas->width) &&
            ((img->height + p->y) <= canvas->height))
    {
        const uint8_t *img_pixel = &image_data[0];
        const uint8_t *img_end = &image_data[img->width * img->height]; 

        for(y0 = 0; y0 < img->height; y0++)
        {
            for(x0 = 0; x0 < img->width; x0++)
            {
                if((sequence == 0) && (nonsequence == 0))
                {
                    if (img_pixel >= img_end){
                        return false; // defensive bounds check
                    }
                    sequence = *img_pixel++;

                    if(sequence < 0)
                    {
                        nonsequence = -sequence;
                        sequence = 0;
                    }
                }

                if(sequence > 0)
                {
                    if (img_pixel >= img_end){
                        return false; // defensive bounds check
                    }

                    *canvas_pixel = *img_pixel;

                    sequence--;

                    if(sequence == 0)
                    {
                        if (img_pixel >= img_end){
                            return false; // defensive bounds check
                        }
                        img_pixel++;
                    }
                }

                if(nonsequence > 0)
                {
                    if (img_pixel >= img_end){
                        return false; // defensive bounds check
                    }

                    *canvas_pixel = *img_pixel++;

                    nonsequence--;
                }

                canvas_pixel++;
            }

            canvas_pixel += (canvas->width - img->width);
        }

        canvas->dirty = true;
        ret_stat = true;
    }

    return(ret_stat);
}

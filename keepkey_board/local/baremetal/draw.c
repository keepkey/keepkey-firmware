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

/// @file keepkey_display.c
/// __One_line_description_of_file.
///
/// __Detailed_description_of_file.


//================================ INCLUDES ===================================

#include <stddef.h>
#include "draw.h"
#include "font.h"
#include "resources.h"


//====================== CONSTANTS, TYPES, AND MACROS =========================


//=============================== VARIABLES ===================================


//=============================== FUNCTIONS ===================================


static bool draw_char_with_shift(Canvas* canvas, DrawableParams* p,
		int* x_shift, int* y_shift, const CharacterImage* img)
{
    bool success = false;

    int start_index = ( p->y * canvas->width ) + p->x;
    uint8_t* canvas_pixel = &canvas->buffer[ start_index ];

    // Check that this was a character that we have in the font.
    if( img != NULL )
    {

        // Check that it's within bounds.
        if( ( ( img->width + p->x ) <= canvas->width ) &&
            ( ( img->height + p->y ) <= canvas->height ) )
        {
            const uint8_t* img_pixel = &img->data[ 0 ]; 

            int y;
            for( y = 0; y < img->height; y++ )
            {
                int x;
                for( x = 0; x < img->width; x++ )
                {
                    *canvas_pixel = ( *img_pixel == 0x00 ) ? p->color : *canvas_pixel;
                    canvas_pixel++;
                    img_pixel++;
                }
                canvas_pixel += ( canvas->width - img->width );
            }

            if( x_shift != NULL )
            {
                *x_shift += img->width;
            }

            if( y_shift != NULL )
            {
                *y_shift += img->height;
            }

            success = true;
        }
    }

    canvas->dirty = true;

    return success;
}

bool draw_string(Canvas* canvas, const Font* font, const char* str_write, DrawableParams* p, int width, int line_height)
{
    bool have_space = true;
    int x_offset = 0;
    DrawableParams char_params = *p;

    while( *str_write && have_space )
    {
    	const CharacterImage* img = font_get_char(font, *str_write);
    	int word_width = img->width;
    	char* next_c = (char *)str_write + 1;

    	/*
    	 * Calculate the next word width while
    	 * removing spacings at beginning of lines
    	 */
    	if(*str_write == ' '){

    		while(*next_c && *next_c != ' ')
    		{
    			word_width += font_get_char(font, *next_c)->width;
    			next_c++;
    		}
    	}

    	/*
    	 * Determine if we need a line break
    	 */
    	if((width != 0) && (x_offset + word_width > width))
    	{
    		char_params.y += line_height;
    		x_offset = 0;
    	}

    	/*
    	 * Remove spaces from beginning of of line
    	 */
    	if(x_offset == 0 && *str_write == ' ')
		{
			str_write++;
			continue;
		}

    	/*
    	 * Draw Character
    	 */
        char_params.x = x_offset + p->x;
        have_space = draw_char_with_shift(
                canvas,
                &char_params,
                &x_offset,
                NULL,
                img);
        str_write++;
    }

    canvas->dirty = true;

    return have_space;
}

bool draw_box(Canvas* canvas, BoxDrawableParams* p)
{
    int start_row = p->base.y;
    int end_row = start_row + p->height;
    end_row = ( end_row >= canvas->height ) ? canvas->height - 1 : end_row; 
    
    int start_col = p->base.x;
    int end_col = p->base.x + p->width;
    end_col = ( end_col >= canvas->width ) ? canvas->width - 1 : end_col; 

    int start_index = ( start_row * canvas->width ) + start_col;
    uint8_t* canvas_pixel = &canvas->buffer[ start_index ];

    int height = end_row - start_row;
    int width = end_col - start_col;

    int y;
    for( y = 0; y < height; y++ )
    {
        int x;
        for( x = 0; x < width; x++ )
        {
            *canvas_pixel = p->base.color;
            canvas_pixel++;
        }
        canvas_pixel += ( canvas->width - width );
    }

    canvas->dirty = true;
    
    return true;
}

bool draw_bitmap_mono_rle(Canvas* canvas, DrawableParams* p, const Image *img)
{
	int x0, y0;
	int8_t sequence = 0;
	int8_t nonsequence = 0;
	uint8_t value = 0;
	static uint8_t image_data[KEEPKEY_DISPLAY_WIDTH * KEEPKEY_DISPLAY_HEIGHT];

    int start_index = ( p->y * canvas->width ) + p->x;
    uint8_t* canvas_pixel = &canvas->buffer[ start_index ];

    /*
     * Get image data
     */
    img->get_image_data(image_data);

	/*
	 * Check that image will fit in bounds
	 */
	if( ( ( img->width + p->x ) <= canvas->width ) &&
		( ( img->height + p->y ) <= canvas->height ) )
	{
		const uint8_t* img_pixel = &image_data[0];

		for( y0 = 0; y0 < img->height; y0++ )
		{
			for( x0 = 0; x0 < img->width; x0++ )
			{
				if ((sequence == 0) && (nonsequence == 0))
				{
					sequence = *img_pixel++;
					if (sequence < 0)
					{
						nonsequence = -sequence;
						sequence = 0;
					}
				}
				if (sequence > 0)
				{
					*canvas_pixel = *img_pixel;

					sequence--;

					if (sequence == 0)
						img_pixel++;
				}
				if (nonsequence > 0)
				{
					*canvas_pixel = *img_pixel++;

					nonsequence--;
				}

				canvas_pixel++;
			}
			canvas_pixel += ( canvas->width - img->width );
		}

		canvas->dirty = true;
		return true;
	}

	return false;
}

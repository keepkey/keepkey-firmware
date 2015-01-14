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

#ifndef KeepKeyFont_H
#define KeepKeyFont_H


#include <stdint.h>

/***************** typedefs and enums  *******************/
/* Data pertaining to the image of a character */
typedef struct
{
    const uint8_t*  data;
    uint16_t        width;
    uint16_t        height;
} CharacterImage;


/* Character information. */
typedef struct
{
    long int                code;
    const CharacterImage*   image;
} Character;


/* A complete font package. */
typedef struct
{
    int                 length;
    int                 size;
    const Character*    characters;
} Font;

/******************* Function Declarations *****************************/
// Get a specific font
const Font* get_pin_font();
const Font* get_title_font();
const Font* get_body_font();

/// Get a character image.
const CharacterImage* font_get_char(const Font* font, char c);

/// Get the height of a font
int font_height(const Font* font);

/// Get the width of a font
int font_width(const Font* font);

// Calculate string width using font data
int calc_str_width(const Font* font, char* str);


#endif // KeepKeyFont_H

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

#ifndef FONT_H
#define FONT_H


#include <stdint.h>


/* Data pertaining to the image of a character */
typedef struct
{
    const uint8_t  *data;
    uint16_t        width;
    uint16_t        height;
} CharacterImage;


/* Character information. */
typedef struct
{
    long int                code;
    const CharacterImage   *image;
} Character;


/* A complete font package. */
typedef struct
{
    int                 length;
    int                 size;
    const Character    *characters;
} Font;


const Font *get_pin_font(void);
const Font *get_title_font(void);
const Font *get_body_font(void);

const CharacterImage *font_get_char(const Font *font, char c);

uint32_t font_height(const Font *font);
uint32_t font_width(const Font *font);

uint32_t calc_str_width(const Font *font, const char *str);
uint32_t calc_str_line(const Font *font, const char *str, uint16_t line_width);

#endif

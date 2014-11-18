/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file KeepKeyFont.h
///

#ifndef KeepKeyFont_H
#define KeepKeyFont_H


//================================ INCLUDES ===================================


#include <stdint.h>


//=================== CONSTANTS, MACROS, AND TYPES ========================


/// Data pertaining to the image of a character
typedef struct
{
    const uint8_t*  data;
    uint16_t        width;
    uint16_t        height;
} CharacterImage;


/// Character information.
typedef struct
{
    long int                code;
    const CharacterImage*   image;
} Character;


/// A complete font package.
typedef struct
{
    int                 length;
    int                 size;
    const Character*    characters;
} Font;



//====================== CLASS MEMBER FUNCTIONS ===========================

// Get a specific font
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

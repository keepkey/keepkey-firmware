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


/// Get a character image.
const CharacterImage* title_font_get_char(char c);
const CharacterImage* body_font_get_char(char c);
const CharacterImage* font_get_char_helper(Font* font, char c);

/// Get the height of a font
int title_font_height(void);
int body_font_height(void);

/// Get the width of a font
int title_font_width(void);
int body_font_width(void);


#endif // KeepKeyFont_H

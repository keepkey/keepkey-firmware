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
const CharacterImage*
font_get_char(
        char c 
);


/// Get the height of a font
int
font_height(
        void
);

/// Get the width of a font
int
font_width(
        void
);


#endif // KeepKeyFont_H

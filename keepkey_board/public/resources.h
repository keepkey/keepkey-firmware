/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file resources.h
///

#ifndef resources_H
#define resources_H


//================================ INCLUDES ===================================


#include <stdint.h>
#include <stdbool.h>


//=================== CONSTANTS, MACROS, AND TYPES ========================


/// Data pertaining to the image
typedef struct
{
    const unsigned char *data;
    uint16_t width;
    uint16_t height;
    uint8_t  dataSize;
} Image;

/// Image frame information.
typedef struct
{
	uint32_t		duration;
    Image*			image;
} ImageFrame;

/// Image animation information.
typedef struct
{
    int                 length;
    const ImageFrame* 	frames;
} ImageAnimation;


typedef struct
{
    const unsigned char *data;
    uint16_t width;
    uint16_t height;
    uint8_t  duration;
} ResourceImage;

typedef enum
{
	CONFIRM_ICON,
    BOOT,
    WIPE
} Resource;


//====================== CLASS MEMBER FUNCTIONS ===========================

const Image* get_home_image();
const ImageAnimation* get_confirm_icon_animation();
const Image* get_image_animation_frame(const ImageAnimation* img_animation, const uint32_t elapsed, bool loop);

#endif // resources_H

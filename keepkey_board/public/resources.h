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
#include "keepkey_display.h"


//=================== CONSTANTS, MACROS, AND TYPES ========================


/// Data pertaining to the image
typedef struct
{
	unsigned char *data;
	uint16_t width;
	uint16_t height;
} Image;

/// Image frame information.
typedef struct
{
	Image*			image;
	uint32_t		duration;
	void* 			(*get_image_data)(uint8_t*);
} AnimationFrame;

/// Image animation information.
typedef struct
{
    int                 length;
    const AnimationFrame* 	frames;
} ImageAnimation;

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

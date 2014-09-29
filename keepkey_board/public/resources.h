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
	void* 		(*get_image_data)(uint8_t*);
	uint16_t 	width;
	uint16_t 	height;
} Image;

/// Image frame information.
typedef struct
{
	Image*			image;
	uint32_t		duration;
} AnimationFrame;

/// Image animation information.
typedef struct
{
    int                 length;
    const AnimationFrame* 	frames;
} ImageAnimation;

typedef enum
{
	HOME_IMG,
    WIPE_BACKGROUND_IMG,
    CONFIRMED_IMG
} ImageResource;

typedef enum
{
	CONFIRM_ICON_ANIM,
	CONFIRMING_ANIM,
    BOOT_ANIM,
    WIPE_ANIM
} AnimationResource;


//====================== CLASS MEMBER FUNCTIONS ===========================

const Image* get_home_image();
const ImageAnimation* get_animation(AnimationResource type);
const uint32_t get_image_animation_duration(const ImageAnimation* img_animation);
const Image* get_image_animation_frame(const ImageAnimation* img_animation, const uint32_t elapsed, bool loop);

#endif // resources_H

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
	const void* (*get_image_data)(uint8_t*);
	uint16_t 	width;
	uint16_t 	height;
} Image;

/// Image frame information.
typedef struct
{
	const Image*	image;
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
	CONFIRM_ICON_ANIM,
	CONFIRMING_ANIM,
    BOOT_ANIM,
    WIPE_ANIM,
    SAVING_ANIM
} AnimationResource;


//====================== CLASS MEMBER FUNCTIONS ===========================

const Image* get_home_image();
const Image* get_wipe_background_image();
const Image* get_saving_background_image();
const Image* get_confirmed_image();

const ImageAnimation* get_confirm_icon_animation();
const ImageAnimation* get_confirming_animation();
const ImageAnimation* get_wipe_animation();
const ImageAnimation* get_saving_animation();
const ImageAnimation* get_boot_animation();

const uint32_t get_image_animation_duration(const ImageAnimation* img_animation);
const Image* get_image_animation_frame(const ImageAnimation* img_animation, const uint32_t elapsed, bool loop);

#endif // resources_H

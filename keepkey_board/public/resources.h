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

#ifndef resources_H
#define resources_H


#include <stdint.h>
#include <stdbool.h>
#include "keepkey_display.h"


/***************** typedefs and enums  *******************/
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
    SAVING_ANIM,
	FLASHING_ANIM,
	SENDING_ANIM,
	SIGNING_ANIM
} AnimationResource;


//====================== CLASS MEMBER FUNCTIONS ===========================

const Image* get_wipe_background_image();
const Image* get_saving_background_image();
const Image* get_flashing_background_image();
const Image* get_sending_background_image();
const Image* get_signing_background_image();
const Image* get_confirmed_image();
const Image* get_unplug_image();

const ImageAnimation* get_screensaver_animation();
const ImageAnimation* get_logo_animation();
const ImageAnimation* get_logo_reversed_animation();
const ImageAnimation* get_confirm_icon_animation();
const ImageAnimation* get_confirming_animation();
const ImageAnimation* get_wipe_animation();
const ImageAnimation* get_saving_animation();
const ImageAnimation* get_warning_animation();
const ImageAnimation* get_flashing_animation();
const ImageAnimation* get_sending_animation();
const ImageAnimation* get_signing_animation();

const uint32_t get_image_animation_duration(const ImageAnimation* img_animation);
const Image* get_image_animation_frame(const ImageAnimation* img_animation, const uint32_t elapsed, bool loop);

const Image* get_recovery_image(void);
#endif // resources_H

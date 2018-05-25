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

#ifndef RESOURCES_H
#define RESOURCES_H

/* === Includes ============================================================ */
#include "keepkey/variant/variant.h"

#include <stdint.h>
#include <stdbool.h>


/* === Defines ============================================================ */

/* === Typedefs ============================================================ */

typedef struct Image_
{
    void (*const get_image_data)(uint8_t *);
    uint16_t    width;
    uint16_t    height;
} Image;

/* Image frame information */
typedef struct AnimationFrame_
{
    const Image    *image;
    uint32_t        duration;
} AnimationFrame;

/* Image animation information */
typedef struct ImageAnimation_
{
    int                     length;
    const AnimationFrame   *frames;
} ImageAnimation;

/* === Functions =========================================================== */

const Image *get_confirm_icon_image(void);
const Image *get_confirmed_image(void);
const Image *get_unplug_image(void);
const Image *get_recovery_image(void);
const Image *get_warning_image(void);

const ImageAnimation *get_confirm_icon_animation(void);
const ImageAnimation *get_confirming_animation(void);
const ImageAnimation *get_loading_animation(void);
const ImageAnimation *get_warning_animation(void);
const VariantAnimation *get_logo_animation(void);
const VariantAnimation *get_logo_reversed_animation(void);
uint16_t get_logo_base_x(void);

uint32_t get_image_animation_duration_new(const VariantAnimation *animation);
uint32_t get_image_animation_duration(const ImageAnimation *img_animation);

const VariantFrame *get_image_animation_frame_new(const VariantAnimation *animation,
                                       const uint32_t elapsed, bool loop);
const Image *get_image_animation_frame(const ImageAnimation *img_animation,
                                       const uint32_t elapsed, bool loop);
#endif

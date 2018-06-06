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

#include "keepkey/board/variant.h"

#include <stdint.h>
#include <stdbool.h>

const AnimationFrame *get_confirm_icon_frame(void);
const AnimationFrame *get_confirmed_frame(void);
const AnimationFrame *get_unplug_frame(void);
const AnimationFrame *get_recovery_frame(void);
const AnimationFrame *get_warning_frame(void);

const VariantAnimation *get_confirming_animation(void);
const VariantAnimation *get_warning_animation(void);
const VariantAnimation *get_logo_animation(void);
const VariantAnimation *get_logo_reversed_animation(void);

uint32_t get_image_animation_duration(const VariantAnimation *animation);
int get_image_animation_frame(const VariantAnimation *animation,
                                       const uint32_t elapsed, bool loop);
#endif

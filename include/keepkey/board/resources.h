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
#include "keepkey/board/variant.h"

#include <stdint.h>
#include <stdbool.h>


/* === Defines ============================================================ */

/* === Functions =========================================================== */

const VariantFrame *get_confirm_icon_image(void);
const VariantFrame *get_confirmed_image(void);
const VariantFrame *get_unplug_image(void);
const VariantFrame *get_recovery_image(void);
const VariantFrame *get_warning_image(void);

const VariantAnimation *get_confirming_animation(void);
const VariantAnimation *get_loading_animation(void);
const VariantAnimation *get_warning_animation(void);
const VariantAnimation *get_logo_animation(void);
const VariantAnimation *get_logo_reversed_animation(void);

uint32_t get_image_animation_duration(const VariantAnimation *animation);
int get_image_animation_frame(const VariantAnimation *animation,
                                       const uint32_t elapsed, bool loop);
#endif

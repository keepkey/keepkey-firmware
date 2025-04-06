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

#ifndef LAYOUT_H
#define LAYOUT_H

#include "keepkey/board/canvas.h"
#include "keepkey/board/resources.h"
#include "keepkey/board/draw.h"

#include <stdint.h>

#define MAX_ANIMATIONS 5
#define ANIMATION_PERIOD 20


/* Vertical Alignment */
#define ONE_LINE 1
#define TWO_LINES 2
#define TOP_MARGIN_FOR_ONE_LINE 20
#define TOP_MARGIN_FOR_TWO_LINES 13
#define TOP_MARGIN_FOR_THREE_LINES 0

/* Margin */
#define TOP_MARGIN 7
#define LEFT_MARGIN 4
#define LEFT_MARGIN_WITH_ICON 40

/* Title */
#define TITLE_COLOR 0xFF
#define TITLE_WIDTH 206
#define TITLE_WIDTH_WITH_ICON TITLE_WIDTH-LEFT_MARGIN_WITH_ICON
#define TITLE_ROWS 1
#define TITLE_FONT_LINE_PADDING 0
#define TITLE_CHAR_MAX 128

/* Body */
#define BODY_TOP_MARGIN 7
#define BODY_COLOR 0xFF
#define BODY_WIDTH 225
#define BODY_WIDTH_WITH_ICON  BODY_WIDTH-LEFT_MARGIN_WITH_ICON
#define BODY_ROWS 3
#define BODY_FONT_LINE_PADDING 4
#define BODY_CHAR_MAX 352

/* Warning */
#define WARNING_COLOR 0xFF
#define WARNING_ROWS 1
#define WARNING_FONT_LINE_PADDING 0

/* Default Layout */
#define NO_WIDTH 0;

typedef enum {
  NOTIFICATION_INFO,
  NOTIFICATION_REQUEST,
  NOTIFICATION_REQUEST_NO_ANIMATION,
  NOTIFICATION_UNPLUG,
  NOTIFICATION_CONFIRM_ANIMATION,
  NOTIFICATION_CONFIRMED,
  NOTIFICATION_LOGO,
} NotificationType;

typedef enum {
  NO_ICON=0,
  ETHEREUM_ICON,
} IconType;

typedef void (*AnimateCallback)(void *data, uint32_t duration,
                                uint32_t elapsed);
typedef struct Animation Animation;
typedef void (*leaving_handler_t)(void);

struct Animation {
  uint32_t duration;
  uint32_t elapsed;
  void *data;
  AnimateCallback animate_callback;
  Animation *next;
};

typedef struct {
  Animation *head;
  int size;

} AnimationQueue;

void layout_has_icon(bool tf);
void layout_init(Canvas *canvas);
Canvas *layout_get_canvas(void);
void call_leaving_handler(void);
void layout_firmware_update_confirmation(void);
void layout_standard_notification(const char *str1, const char *str2,
                                  NotificationType type);
void layout_constant_power_notification(const char *str1, const char *str2, NotificationType type);
void layout_notification_icon(NotificationType type, DrawableParams *sp);
void layout_add_icon(IconType type);
void layout_warning(const char *prompt);
void layout_warning_static(const char *str);
void layout_simple_message(const char *str);
void layout_version(int32_t major, int32_t minor, int32_t patch);
void layout_home(void);
void layout_home_reversed(void);
void animate(void);
bool is_animating(void);
void force_animation_start(void);
void animating_progress_handler(const char *desc, int permil);
void layoutProgress(const char *desc, int permil);
void layoutProgressForAuth(const char *otp, const char *desc, int permil);
void layoutProgressSwipe(const char *desc, int permil);
void layout_add_animation(AnimateCallback callback, void *data,
                          uint32_t duration);
void layout_animate_images(void *data, uint32_t duration, uint32_t elapsed);
void layout_clear(void);
#if DEBUG_LINK
void layout_debuglink_watermark(void);
#endif
void layout_clear_animations(void);
void layout_clear_static(void);

void kk_strupr(char *str);
void kk_strlwr(char *str);
#endif

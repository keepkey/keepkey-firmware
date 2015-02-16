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

//============================= CONDITIONALS ==================================


#ifndef layout_H
#define layout_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "canvas.h"
#include "resources.h"


/*******************  Defines ************************/
#define MAX_ANIMATIONS 5
#define ANIMATION_PERIOD 20

/* Margin */
#define TOP_MARGIN 	7
#define LEFT_MARGIN	4

/* Title */
#define TITLE_COLOR 			0xFF
#define TITLE_WIDTH 			206
#define TITLE_ROWS 				1
#define TITLE_FONT_LINE_PADDING 0

/* Body */
#define BODY_COLOR				0xFF
#define BODY_WIDTH				206
#define BODY_ROWS				3
#define BODY_FONT_LINE_PADDING	2

/* Warning */
#define WARNING_COLOR 				0xFF
#define WARNING_WIDTH				256
#define WARNING_ROWS				1
#define WARNING_FONT_LINE_PADDING	0

/* Default Layout */
#define NO_WIDTH 0;

#define AMOUNT_LABEL_TEXT	"Amount:"
#define ADDRESS_LABEL_TEXT	"Address:"
#define CONFIRM_LABEL_TEXT	"Confirming transaction..."

/**************  Typedefs and Macros *****************/
typedef enum
{
	NOTIFICATION_INFO,
    NOTIFICATION_REQUEST,
	NOTIFICATION_RECOVERY,
	NOTIFICATION_UNPLUG,
    NOTIFICATION_CONFIRM_ANIMATION,
    NOTIFICATION_CONFIRMED
} NotificationType;

typedef void (*leaving_handler_t)(void);
typedef void (*AnimateCallback)(void* data, uint32_t duration, uint32_t elapsed);
typedef struct Animation Animation;

struct Animation
{
    uint32_t        duration;
    uint32_t        elapsed;
 
    void*           data;
    AnimateCallback animate_callback;

    Animation*      next;
};

typedef struct
{
    Animation*  head;
    int         size;

} AnimationQueue;

/**************  Function Declarations ****************/
void layout_init( Canvas* canvas);
void layout_home(void);
void layout_home_reversed(void);
void layout_screensaver(void);
void layout_tx_info( const char* address, uint64_t amount_in_satoshi);
void layout_confirmation(); 
uint32_t layout_char_width();
uint32_t title_char_width();
uint32_t body_char_width();
uint32_t warning_char_width();

void layout_firmware_update_confirmation();
void layout_standard_notification( const char* str1, const char* str2, NotificationType type);
void layout_warning(const char* prompt);
void layout_pin(const char *prompt, char *pin);
void layout_loading(AnimationResource type);

void animate( void);
bool is_animating(void);
void force_animation_start(void);
void animating_progress_handler(void);
void animating_progress_slowed_handler(void);
void layout_add_animation(AnimateCallback callback, void* data, uint32_t duration);

void layout_clear();
void layout_clear_animations();
void layout_clear_static();

void set_leaving_handler(leaving_handler_t leaving_func);
static void call_leaving_handler(void);


#ifdef __cplusplus
}
#endif

#endif // layout_H


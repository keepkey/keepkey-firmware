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
#include "draw.h"


/*******************  Defines ************************/
#define MAX_ANIMATIONS 5
#define ANIMATION_PERIOD 20

/* Vertical Alignment */
#define ONE_LINE 1
#define TWO_LINES 2
#define TOP_MARGIN_FOR_ONE_LINE 20
#define TOP_MARGIN_FOR_TWO_LINES 13

/* Margin */
#define TOP_MARGIN 	7
#define LEFT_MARGIN	4

/* Title */
#define TITLE_COLOR 			0xFF
#define TITLE_WIDTH 			206
#define TITLE_ROWS 				1
#define TITLE_FONT_LINE_PADDING 0
#define TITLE_CHAR_MAX          128

/* Body */
#define BODY_TOP_MARGIN 		7
#define BODY_COLOR				0xFF
#define BODY_WIDTH				225
#define BODY_ROWS				3
#define BODY_FONT_LINE_PADDING	4
#define BODY_CHAR_MAX           352

/* Transaction */
#define TRANSACTION_TOP_MARGIN  4
#define TRANSACTION_WIDTH       250

/* Warning */
#define WARNING_COLOR 				0xFF
#define WARNING_ROWS				1
#define WARNING_FONT_LINE_PADDING	0

/* Default Layout */
#define NO_WIDTH 0;

/* PIN Matrix */
#define MATRIX_MASK_COLOR                   0x00
#define MATRIX_MASK_MARGIN                  3
#define PIN_MATRIX_GRID_SIZE                18
#define PIN_MATRIX_ANIMATION_FREQUENCY_MS	40
#define PIN_MATRIX_BACKGROUND 				0x11
#define PIN_MATRIX_STEP1	 				0x11
#define PIN_MATRIX_STEP2	 				0x33
#define PIN_MATRIX_STEP3	 				0x77
#define PIN_MATRIX_STEP4	 				0xBB
#define PIN_MATRIX_FOREGROUND 				0xFF
#define PIN_SLIDE_DELAY						20
#define PIN_MAX_ANIMATION_MS				1000

/* Recovery Cypher */
#define CIPHER_ROWS                     2
#define CIPHER_LETTER_BY_ROW            13
#define CIPHER_GRID_SIZE                13
#define CIPHER_GRID_SPACING             1
#define CIPHER_ANIMATION_FREQUENCY_MS   20
#define CIPHER_STEP_1                   0X22
#define CIPHER_STEP_2                   0X33
#define CIPHER_STEP_3                   0X55
#define CIPHER_STEP_4                   0X77
#define CIPHER_FOREGROUND               0X99
#define CIPHER_START_X                  76
#define CIPHER_START_Y                  3
#define CIPHER_MASK_COLOR               0x00
#define CIPHER_FONT_COLOR               0x99
#define CIPHER_MAP_FONT_COLOR           0xFF
#define CIPHER_HORIZONTAL_MASK_WIDTH    181
#define CIPHER_HORIZONTAL_MASK_WIDTH_3  3
#define CIPHER_HORIZONTAL_MASK_HEIGHT_2 2
#define CIPHER_HORIZONTAL_MASK_HEIGHT_3 3
#define CIPHER_HORIZONTAL_MASK_HEIGHT_4 4

/* QR */
#define ADDRESS_TOP_MARGIN      16
#define MULTISIG_LEFT_MARGIN    40
#define QR_DISPLAY_SCALE        1
#define QR_DISPLAY_X            4
#define QR_DISPLAY_Y            10

/**************  Typedefs and Macros *****************/
typedef enum
{
	NOTIFICATION_INFO,
    NOTIFICATION_REQUEST,
	NOTIFICATION_REQUEST_NO_ANIMATION,
	NOTIFICATION_RECOVERY,
	NOTIFICATION_UNPLUG,
    NOTIFICATION_CONFIRM_ANIMATION,
    NOTIFICATION_CONFIRMED
} NotificationType;

typedef enum
{
	SLIDE_DOWN,
	SLIDE_LEFT,
	SLIDE_UP,
	SLIDE_RIGHT
} PINAnimationDirection;

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

typedef struct
{
	PINAnimationDirection direction;
    uint32_t elapsed_start_ms;
} PINAnimationConfig;

/**************  Function Declarations ****************/
void layout_init( Canvas* canvas);
void layout_home(void);
void layout_home_reversed(void);
void layout_screensaver(void);
void layout_tx_info( const char* address, uint64_t amount_in_satoshi);
void layout_confirmation(); 
const uint32_t layout_char_width();
const uint32_t warning_char_width();

void layout_firmware_update_confirmation();
void layout_standard_notification( const char* str1, const char* str2, NotificationType type);
void layout_transaction_notification(const char* amount, const char* address, NotificationType type);
void layout_address_notification(const char* desc, const char* address, NotificationType type);
void layout_notification_icon(NotificationType type, DrawableParams *sp);
void layout_warning(const char* prompt);
void layout_simple_message(const char* str);
void layout_pin(const char *prompt, char *pin);
void layout_cipher(const char* current_word, const char* cipher);
void layout_loading();
void layout_address(const char* address);

void animate( void);
bool is_animating(void);
void force_animation_start(void);
void animating_progress_handler(void);
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


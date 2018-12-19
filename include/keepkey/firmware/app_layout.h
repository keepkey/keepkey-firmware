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

#ifndef APP_LAYOUT_H
#define APP_LAYOUT_H


#include "keepkey/board/canvas.h"
#include "keepkey/board/resources.h"
#include "keepkey/board/draw.h"

#include <stdint.h>


/* Screen Test */
#define TEST_COLOR      0xFF
#define TEST_X          1
#define TEST_Y          1
#define TEST_WIDTH      256
#define TEST_HEIGHT     64

/* Transaction */
#define TRANSACTION_TOP_MARGIN  4
#define TRANSACTION_WIDTH       250
#define NO_TITLE_WIDTH          250

/* PIN Matrix */
#define MATRIX_MASK_COLOR                   0x00
#define MATRIX_MASK_MARGIN                  3
#define PIN_MATRIX_GRID_SIZE                18
#define PIN_MATRIX_ANIMATION_FREQUENCY_MS   40
#define PIN_MATRIX_BACKGROUND               0x11
#define PIN_MATRIX_STEP1                    0x11
#define PIN_MATRIX_STEP2                    0x33
#define PIN_MATRIX_STEP3                    0x77
#define PIN_MATRIX_STEP4                    0xBB
#define PIN_MATRIX_FOREGROUND               0xFF
#define PIN_SLIDE_DELAY                     20
#define PIN_MAX_ANIMATION_MS                1000
#define PIN_LEFT_MARGIN                     140

/* Recovery Cypher */
#define CIPHER_ROWS                     2
#define CIPHER_LETTER_BY_ROW            13
#define CIPHER_GRID_SIZE                13
#define CIPHER_GRID_SPACING             1
#define CIPHER_ANIMATION_FREQUENCY_MS   10
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
#define ADDRESS_XPUB_TOP_MARGIN 14
#define MULTISIG_LEFT_MARGIN    40
#define QR_DISPLAY_SCALE        1
#define QR_DISPLAY_X            4
#define QR_DISPLAY_Y            10


typedef enum
{
    SLIDE_DOWN,
    SLIDE_LEFT,
    SLIDE_UP,
    SLIDE_RIGHT
} PINAnimationDirection;

typedef enum
{
    QR_LARGE,
    QR_SMALL
} QRSize;

typedef struct
{
    PINAnimationDirection direction;
    uint32_t elapsed_start_ms;
} PINAnimationConfig;


void layout_screen_test(void);
void layout_screensaver(void);
void layout_tx_info(const char *address, uint64_t amount_in_satoshi);
void layout_notification_no_title(const char *title, const char *body,
                                  NotificationType type, bool bold);
void layout_notification_no_title_bold(const char *title, const char *body,
                                       NotificationType type);
void layout_notification_no_title_no_bold(const char *title, const char *body,
        NotificationType type);
void layout_xpub_notification(const char *desc, const char *xpub,
                              NotificationType type);
void layout_address_notification(const char *desc, const char *address,
                                 NotificationType type);
void layout_ethereum_address_notification(const char *desc, const char *address,
        NotificationType type);
void layout_pin(const char *prompt, char *pin);
void layout_cipher(const char *current_word, const char *cipher);
void layout_address(const char *address, QRSize qr_size);
void set_leaving_handler(leaving_handler_t leaving_func);

#endif

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


#include "keepkey/board/layout.h"
#include "keepkey/board/draw.h"
#include "keepkey/board/font.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/variant.h"

#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/app_resources.h"
#include "keepkey/firmware/fsm.h"

#include "trezor/qrenc/qr_encode.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>



/*
 * layout_animate_pin() - Animate pin scramble
 *
 * INPUT
 *     - data: pointer to pin array
 *     - duration: duration of the pin scramble animation
 *     - elapsed: how long we have animating
 * OUTPUT
 *     none
 */
static void layout_animate_pin(void *data, uint32_t duration, uint32_t elapsed)
{
    (void)duration;
    BoxDrawableParams box_params = {{0x00, 0, 0}, 64, 256};
    DrawableParams sp;
    Canvas *canvas = layout_get_canvas();
    char *pin = (char *)data;
    const uint8_t color_stepping[] = {PIN_MATRIX_STEP1, PIN_MATRIX_STEP2, PIN_MATRIX_STEP3, PIN_MATRIX_STEP4, PIN_MATRIX_FOREGROUND};

    const Font *pin_font = get_pin_font();

    /* Draw matrix */
    box_params.base.color = PIN_MATRIX_BACKGROUND;

    for(uint8_t row = 0; row < 3; row++)
    {
        for(uint8_t col = 0; col < 3; col++)
        {
            box_params.base.y = 5 + row * 19;
            box_params.base.x = PIN_LEFT_MARGIN + col * 19;
            box_params.height = 18;
            box_params.width = 18;
            draw_box(canvas, &box_params);
        }
    }

    /* Configure each PIN digit animation settings */
    const PINAnimationConfig pin_animation_cfg[] =
    {
        {SLIDE_RIGHT, 8 * PIN_SLIDE_DELAY}, // 1
        {SLIDE_UP, 7 * PIN_SLIDE_DELAY},    // 2
        {SLIDE_DOWN, 6 * PIN_SLIDE_DELAY},  // 3
        {SLIDE_LEFT, 5 * PIN_SLIDE_DELAY},  // 4
        {SLIDE_UP, 4 * PIN_SLIDE_DELAY},    // 5
        {SLIDE_RIGHT, 3 * PIN_SLIDE_DELAY}, // 6
        {SLIDE_UP, 0 * PIN_SLIDE_DELAY},    // 7
        {SLIDE_RIGHT, 1 * PIN_SLIDE_DELAY}, // 8
        {SLIDE_DOWN, 2 * PIN_SLIDE_DELAY}   // 9
    };

    /* Draw each pin digit individually base on animation config on matrix position */
    for(uint8_t row = 0; row < 3; row++)
    {
        for(uint8_t col = 0; col < 3; col++)
        {

            uint8_t cur_pos = col + (2 - row) * 3;
            const PINAnimationConfig *cur_pos_cfg = &pin_animation_cfg[cur_pos];
            uint32_t cur_pos_elapsed = elapsed - cur_pos_cfg->elapsed_start_ms;

            /* Skip position is enough time has not passed */
            if(cur_pos_cfg->elapsed_start_ms > elapsed)
            {
                continue;
            }

            /* Determine color */
            sp.color = PIN_MATRIX_FOREGROUND;

            for(uint8_t color_index = 0;
                    color_index < sizeof(color_stepping) / sizeof(color_stepping[0]); color_index++)
            {
                if(cur_pos_elapsed < (color_index * PIN_MATRIX_ANIMATION_FREQUENCY_MS))
                {
                    sp.color = color_stepping[color_index];
                    break;
                }
            }

            uint8_t pad = 7;

            /* Adjust pad */
            if(pin[cur_pos] == '1')
            {
                pad++;
            }

            sp.y = 8 + row * 19;
            sp.x = (PIN_LEFT_MARGIN - 2) + pad + col * 19;

            uint8_t adj_pos = cur_pos_elapsed / 40;

            if(adj_pos <= 5)
            {
                adj_pos = 5 - adj_pos;

                switch(cur_pos_cfg->direction)
                {
                    case SLIDE_DOWN:
                        sp.y -= adj_pos;
                        break;

                    case SLIDE_LEFT:
                        sp.x += adj_pos;
                        break;

                    case SLIDE_UP:
                        sp.y += adj_pos;
                        break;

                    case SLIDE_RIGHT:
                    default:
                        sp.x -= adj_pos;
                        break;
                }
            }

            draw_char(canvas, pin_font, pin[cur_pos], &sp);
        }
    }

    /* Mask horizontally */
    draw_box_simple(canvas, MATRIX_MASK_COLOR, PIN_LEFT_MARGIN -3, 2, PIN_MATRIX_GRID_SIZE * 3 + 8,
                    MATRIX_MASK_MARGIN);
    draw_box_simple(canvas, MATRIX_MASK_COLOR, PIN_LEFT_MARGIN -3, 5 + PIN_MATRIX_GRID_SIZE,
                    PIN_MATRIX_GRID_SIZE * 3 + 8, 1);
    draw_box_simple(canvas, MATRIX_MASK_COLOR, PIN_LEFT_MARGIN -3, 6 + PIN_MATRIX_GRID_SIZE * 2,
                    PIN_MATRIX_GRID_SIZE * 3 + 8, 1);
    draw_box_simple(canvas, MATRIX_MASK_COLOR, PIN_LEFT_MARGIN - 3, 7 + PIN_MATRIX_GRID_SIZE * 3,
                    PIN_MATRIX_GRID_SIZE * 3 + 8, MATRIX_MASK_MARGIN);

    /* Mask vertically */
    draw_box_simple(canvas, MATRIX_MASK_COLOR, PIN_LEFT_MARGIN - 3, 2, MATRIX_MASK_MARGIN, 18 * 3 + 8);
    draw_box_simple(canvas, MATRIX_MASK_COLOR, PIN_LEFT_MARGIN + PIN_MATRIX_GRID_SIZE, 2, 1,
                    PIN_MATRIX_GRID_SIZE * 3 + 8);
    draw_box_simple(canvas, MATRIX_MASK_COLOR, PIN_LEFT_MARGIN + 1 + PIN_MATRIX_GRID_SIZE * 2, 2, 1,
                    PIN_MATRIX_GRID_SIZE * 3 + 8);
    draw_box_simple(canvas, MATRIX_MASK_COLOR, PIN_LEFT_MARGIN + 2 + PIN_MATRIX_GRID_SIZE * 3, 2,
                    MATRIX_MASK_MARGIN, PIN_MATRIX_GRID_SIZE * 3 + 8);
}

/*
 * layout_animate_cipher() - Animate recovery cipher
 *
 * INPUT
 *     - data: pointer to pin array
 *     - duration: duration of the pin scramble animation
 *     - elapsed: how long we have been animating
 * OUTPUT
 *     none
 */
static void layout_animate_cipher(void *data, uint32_t duration, uint32_t elapsed)
{
    (void)duration;
    Canvas *canvas = layout_get_canvas();
    int row, letter, x_padding, cur_pos_elapsed, adj_pos, adj_x, adj_y, cur_index;
    char *cipher = (char *)data;
    char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
    char *current_letter = alphabet;

    DrawableParams sp;
    const Font *title_font = get_title_font();
    const Font *cipher_font = get_body_font();

    /* Clear area behind cipher */
    draw_box_simple(canvas, CIPHER_MASK_COLOR, CIPHER_START_X, 0,
                    KEEPKEY_DISPLAY_WIDTH - CIPHER_START_X, KEEPKEY_DISPLAY_HEIGHT);

    /* Draw grid */
    sp.y = CIPHER_START_Y;
    sp.x = CIPHER_START_X;

    for(row = 0; row < CIPHER_ROWS; row++)
    {
        for(letter = 0; letter < CIPHER_LETTER_BY_ROW; letter++)
        {
            cur_index = (row * CIPHER_LETTER_BY_ROW) + letter;
            cur_pos_elapsed = elapsed - cur_index * CIPHER_ANIMATION_FREQUENCY_MS;
            sp.x = CIPHER_START_X + (letter * (CIPHER_GRID_SIZE + CIPHER_GRID_SPACING));
            x_padding = 0;

            /* Draw grid */
            draw_box_simple(canvas, CIPHER_STEP_1, sp.x - 4, sp.y + CIPHER_GRID_SIZE,
                            CIPHER_GRID_SIZE, CIPHER_GRID_SIZE);

            x_padding = 0;

            if(*current_letter == 'i' || *current_letter == 'l')
            {
                x_padding = 2;
            }
            else if(*current_letter == 'm' || *current_letter == 'w')
            {
                x_padding = -1;
            }

            /* Draw map */
            draw_char_simple(canvas, title_font, *current_letter++, CIPHER_MAP_FONT_COLOR,
                             sp.x + x_padding, sp.y);

            x_padding = 0;

            if(*cipher == 'i' || *cipher == 'l')
            {
                x_padding = 2;
            }
            else if(*cipher == 'k' || *cipher == 'j' ||
                    *cipher == 'r' || *cipher == 'f')
            {
                x_padding = 1;
            }
            else if(*cipher == 'm' || *cipher == 'w')
            {
                x_padding = -1;
            }

            /* Draw cipher */
            if(cur_pos_elapsed > 0)
            {
                adj_pos = cur_pos_elapsed / CIPHER_ANIMATION_FREQUENCY_MS;

                adj_x = 0;
                adj_y = 0;

                if(adj_pos < 5)
                {
                    if(cur_index % 4 == 0)
                    {
                        adj_y = -(5 - adj_pos);
                    }
                    else if(cur_index % 4 == 1)
                    {
                        adj_x = 5 - adj_pos;
                    }
                    else if(cur_index % 4 == 2)
                    {
                        adj_y = 5 - adj_pos;
                    }
                    else
                    {
                        adj_x = -(5 - adj_pos);
                    }
                }

                draw_char_simple(canvas, cipher_font, *cipher, CIPHER_FONT_COLOR,
                                 sp.x + x_padding + adj_x, sp.y + (CIPHER_GRID_SIZE + CIPHER_GRID_SPACING) + adj_y);
            }

            /* Draw grid mask between boxes */
            draw_box_simple(canvas, CIPHER_MASK_COLOR, sp.x - 5, sp.y + CIPHER_GRID_SIZE, 1,
                            CIPHER_GRID_SIZE);

            cipher++;
        }

        sp.x = CIPHER_START_X;
        sp.y += 31;
    }

    /* Draw mask */
    draw_box_simple(canvas, CIPHER_MASK_COLOR, CIPHER_START_X - 4, 14,
                    CIPHER_HORIZONTAL_MASK_WIDTH,
                    CIPHER_HORIZONTAL_MASK_HEIGHT_2);
    draw_box_simple(canvas, CIPHER_MASK_COLOR, CIPHER_START_X - 4, 45,
                    CIPHER_HORIZONTAL_MASK_WIDTH,
                    CIPHER_HORIZONTAL_MASK_HEIGHT_2);
    draw_box_simple(canvas, CIPHER_MASK_COLOR, CIPHER_START_X - 4, 29,
                    CIPHER_HORIZONTAL_MASK_WIDTH,
                    CIPHER_HORIZONTAL_MASK_HEIGHT_3);
    draw_box_simple(canvas, CIPHER_MASK_COLOR, CIPHER_START_X - 4, 59,
                    CIPHER_HORIZONTAL_MASK_WIDTH,
                    CIPHER_HORIZONTAL_MASK_HEIGHT_4);
    draw_box_simple(canvas, CIPHER_MASK_COLOR,
                    KEEPKEY_DISPLAY_WIDTH - CIPHER_HORIZONTAL_MASK_WIDTH_3, 0,
                    CIPHER_HORIZONTAL_MASK_WIDTH_3, KEEPKEY_DISPLAY_HEIGHT);
}


/*
 *  layout_screen_test() - Display screen test
 *
 *  INPUT
 *      none
 *  OUTPUT
 *      none
 */
void layout_screen_test(void)
{
    draw_box_simple(layout_get_canvas(), TEST_COLOR, TEST_X, TEST_Y, TEST_WIDTH, TEST_HEIGHT);
}

/*
 *  layout_screensaver() - Displays screensaver
 *
 *  INPUT
 *      none
 *  OUTPUT
 *      none
 */
void layout_screensaver(void)
{
    draw_box_simple(layout_get_canvas(), 0x00, 0, 0,
                    KEEPKEY_DISPLAY_WIDTH,
                    KEEPKEY_DISPLAY_HEIGHT);

    layout_add_animation(
        &layout_animate_images,
        (void *)variant_getScreensaver(),
        0);
}

/*
 * layout_notification_no_title() - Display notification without title
 *
 * INPUT
 *     - title
 *     - body
 * OUTPUT
 *     none
 */
void layout_notification_no_title(const char *title, const char *body,
                                  NotificationType type, bool bold)
{
    (void)title;
    call_leaving_handler();
    layout_clear();

    Canvas *canvas = layout_get_canvas();
    DrawableParams sp;
    const Font *font = get_title_font();

    if (!bold) {
        font = get_body_font();
    }

    /* Determine vertical alignment and body width */
    sp.y =  TOP_MARGIN_FOR_ONE_LINE;

    /* Draw */
    sp.x = LEFT_MARGIN;
    sp.color = TITLE_COLOR;
    draw_string(canvas, font, body, &sp, NO_TITLE_WIDTH, font_height(font));

    layout_notification_icon(type, &sp);
}

/*
 * layout_notification_no_title_bold() - Display notification without title in bold
 *
 * INPUT
 *     - title
 *     - body
 * OUTPUT
 *     none
 */
void layout_notification_no_title_bold(const char *title, const char *body,
                                  NotificationType type)
{
    layout_notification_no_title(title, body, type, true);
}

/*
 * layout_notification_no_title_no_bold() - Display notification without title without bold
 *
 * INPUT
 *     - title
 *     - body
 * OUTPUT
 *     none
 */
void layout_notification_no_title_no_bold(const char *title, const char *body,
                                  NotificationType type)
{
    layout_notification_no_title(title, body, type, false);
}

/*
 * layout_xpub_notification() - Display extended public address (xpub) notification
 *
 * INPUT
 *     - xpub: address to display both as string
 *     - type: notification type
 * OUTPUT
 *      none
 */
void layout_xpub_notification(const char *desc, const char *xpub,
                              NotificationType type)
{
    (void)desc;
    call_leaving_handler();
    layout_clear();

    Canvas *canvas = layout_get_canvas();
    DrawableParams sp;
    const Font *xpub_font = get_body_font();

    if (strcmp(desc, "") != 0)
    {
        const Font *title_font = get_title_font();
        sp.y = TOP_MARGIN_FOR_THREE_LINES;
        sp.x = LEFT_MARGIN;
        sp.color = BODY_COLOR;
        draw_string(canvas, title_font, desc, &sp, TRANSACTION_WIDTH - 2,
                    font_height(title_font) + BODY_FONT_LINE_PADDING);
    }

    /* Determine vertical alignment and body width */
    sp.y =  TOP_MARGIN_FOR_THREE_LINES + ADDRESS_XPUB_TOP_MARGIN;
    sp.x = LEFT_MARGIN;
    sp.color = BODY_COLOR;
    draw_string(canvas, xpub_font, xpub, &sp, TRANSACTION_WIDTH - 25,
                font_height(xpub_font) + BODY_FONT_LINE_PADDING);

    layout_notification_icon(type, &sp);
}

/*
 * layout_ethereum_address_notification() - Display ethereum address notification
 *
 * INPUT
 *     - desc: description of address being shown (normal or multisig)
 *     - address: ethereum address to display both as string and QR
 *     - type: notification type
 * OUTPUT
 *      none
 */
void layout_ethereum_address_notification(const char *desc, const char *address,
        NotificationType type)
{
    DrawableParams sp;
    const Font *address_font = get_body_font();;
    Canvas *canvas = layout_get_canvas();

    call_leaving_handler();
    layout_clear();

    if (strcmp(desc, "") != 0) {
        const Font *title_font = get_title_font();
        sp.y = TOP_MARGIN_FOR_TWO_LINES;
        sp.x = LEFT_MARGIN + 65;
        sp.color = BODY_COLOR;
        draw_string(canvas, title_font, desc, &sp, TRANSACTION_WIDTH - 2,
                    font_height(title_font) + BODY_FONT_LINE_PADDING);
    }

    /* Body */
    sp.y =  TOP_MARGIN_FOR_TWO_LINES + TOP_MARGIN + TOP_MARGIN;
    sp.x = LEFT_MARGIN + 65;
    sp.color = BODY_COLOR;

    draw_string(canvas, address_font, address, &sp, 140,
                font_height(address_font) + BODY_FONT_LINE_PADDING);

    layout_address(address, QR_LARGE);
    layout_notification_icon(type, &sp);
}

/*
 * layout_address_notification() - Display address notification
 *
 * INPUT
 *     - desc: description of address being shown (normal or multisig)
 *     - address: address to display both as string and QR
 *     - type: notification type
 * OUTPUT
 *      none
 */
void layout_address_notification(const char *desc, const char *address,
                                 NotificationType type)
{
    call_leaving_handler();
    layout_clear();

    Canvas *canvas = layout_get_canvas();
    DrawableParams sp;
    const Font *address_font = get_title_font();

    /* Unbold fonts if address becomes too long */
    if(calc_str_width(address_font, address) > TRANSACTION_WIDTH)
    {
        address_font = get_body_font();
    }

    /* Determine vertical alignment and body width */
    sp.y =  TOP_MARGIN_FOR_ONE_LINE;

    /* Draw address */
    sp.y += font_height(address_font) + ADDRESS_TOP_MARGIN;
    sp.x = LEFT_MARGIN;
    sp.color = BODY_COLOR;
    draw_string(canvas, address_font, address, &sp, TRANSACTION_WIDTH,
                font_height(address_font) + BODY_FONT_LINE_PADDING);

    /* Draw description */
    if (strcmp(desc, "") != 0) {
        const uint32_t title_line_count = calc_str_line(address_font, desc, BODY_WIDTH);

        sp.y = TOP_MARGIN;
        if (title_line_count == ONE_LINE) {
            sp.y = TOP_MARGIN_FOR_ONE_LINE;
        } else if(title_line_count == TWO_LINES) {
            sp.y = TOP_MARGIN_FOR_TWO_LINES;
        }

        sp.x = MULTISIG_LEFT_MARGIN;
        sp.color = BODY_COLOR;
        draw_string(canvas, address_font, desc, &sp, TRANSACTION_WIDTH - 2,
                    font_height(address_font) + BODY_FONT_LINE_PADDING);
    }

    layout_address(address, QR_SMALL);
    layout_notification_icon(type, &sp);
}

/*
 * layout_pin() - Draws pin matrix
 *
 * INPUT
 *     - str: string prompt to display next to pin matrix
 *     - pin: randomized pin matric
 * OUTPUT
 *     none
 */
void layout_pin(const char *str, char pin[])
{
    DrawableParams sp;
    Canvas *canvas = layout_get_canvas();

    call_leaving_handler();
    layout_clear();

    /* Draw prompt */
    const Font *font = get_body_font();
    sp.y = 29;
    sp.x = (140 - calc_str_width(font, str)) / 2;
    sp.color = BODY_COLOR;
    draw_string(canvas, font, str, &sp, TITLE_WIDTH, font_height(font));
    display_refresh();

    /* Animate pin scrambling */
    layout_add_animation(&layout_animate_pin, (void *)pin, PIN_MAX_ANIMATION_MS);
}

/*
 * layout_cipher() - Draws recover cipher
 *
 * INPUT
 *     - current_word: current word that is being typed in at this point in recovery
 *     - cipher: randomized cipher
 * OUTPUT
 *     none
 */
void layout_cipher(const char *current_word, const char *cipher)
{
    DrawableParams sp;
    const Font *title_font = get_body_font();
    Canvas *canvas = layout_get_canvas();

    call_leaving_handler();
    layout_clear();

    /* Draw prompt */
    sp.y = 11;
    sp.x = 4;
    sp.color = BODY_COLOR;
    draw_string(canvas, title_font, "Recovery Cipher:", &sp, 58, font_height(title_font) + 3);

    /* Draw current word */
    sp.y = 46;
    sp.x = 4;
    sp.color = BODY_COLOR;
    draw_string(canvas, title_font, current_word, &sp, 68, font_height(title_font));
    display_refresh();

    /* Animate cipher */
    layout_add_animation(&layout_animate_cipher, (void *)cipher,
                         CIPHER_ANIMATION_FREQUENCY_MS * 30);
}

/*
 * layout_address() - Draws QR code of address
 *
 * INPUT
 *     - address: address to QR code for
 * OUTPUT
 *     none
 */
void layout_address(const char *address, QRSize qr_size)
{
    static unsigned char bitdata[QR_MAX_BITDATA];
    Canvas *canvas = layout_get_canvas();

    int a, i, j, side, y_pos = QR_DISPLAY_Y;

    if(qr_size == QR_SMALL)
    {
        side = qr_encode(QR_LEVEL_M, 0, address, 0, bitdata);
    }
    else
    {
        side = qr_encode(QR_LEVEL_M, 8, address, 0, bitdata);
        y_pos -= 4;
    }

    /* Limit QR to version 1-9 (QR size <= 53) */
    if(side > 0 && side <= 53)
    {
        /* Draw QR background */
        draw_box_simple(canvas, 0xFF, QR_DISPLAY_X, y_pos,
                        (side + 2) * QR_DISPLAY_SCALE, (side + 2) * QR_DISPLAY_SCALE);

        /* Fill in QR */
        for(i = 0; i < side; i++)
        {
            for(j = 0; j < side; j++)
            {
                a = j * side + i;

                if(bitdata[a / 8] & (1 << (7 - a % 8)))
                {
                    draw_box_simple(canvas, 0x00,
                                    QR_DISPLAY_SCALE + (i + QR_DISPLAY_X) * QR_DISPLAY_SCALE,
                                    QR_DISPLAY_SCALE + (j + y_pos) * QR_DISPLAY_SCALE,
                                    QR_DISPLAY_SCALE, QR_DISPLAY_SCALE);
                }
            }
        }
    }
}

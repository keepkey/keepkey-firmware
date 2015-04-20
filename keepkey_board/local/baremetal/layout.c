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

//================================ INCLUDES ===================================

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "draw.h"
#include "font.h"
#include "keepkey_display.h"
#include "layout.h"
#include "timer.h"
#include "resources.h"
#include "qr_encode.h"

/* variable definitions  */
static AnimationQueue active_queue = { NULL, 0 };
static AnimationQueue free_queue = { NULL, 0 };
static Animation animations[ MAX_ANIMATIONS ];
static Canvas* canvas = NULL;
static volatile bool animate_flag = false;
static leaving_handler_t leaving_handler;

/* Standard time to wait for the confirmation.  */
static const uint32_t STANDARD_CONFIRM_MS = 2000;

/* static function */

static void layout_home_helper(bool reversed);

static void layout_animate_callback( void* context );

#if defined(AGGRO_UNDEFINED_FN)
static void layout_remove_animation( AnimateCallback  callback);  
#endif

static void animation_queue_push( AnimationQueue *queue, Animation *node);
static Animation *animation_queue_pop( AnimationQueue *queue);
static Animation *animation_queue_peek( AnimationQueue *queue);
static Animation* animation_queue_get( AnimationQueue *queue, AnimateCallback callback);
static void layout_animate_images(void *data, uint32_t duration, uint32_t elapsed);
static void layout_animate_pin(void *data, uint32_t duration, uint32_t elapsed);
static void layout_animate_cipher(void* data, uint32_t duration, uint32_t elapsed);

/*
 * layout_init() - Initialize layout subsystem for LCD screen
 * 
 * INPUT -
 *     lay out info for specific image
 * OUTPUT - 
 *     none
 */
void layout_init(Canvas* new_canvas)
{
    canvas = new_canvas;

    int i;
    for( i = 0; i < MAX_ANIMATIONS; i++ ) {
        animation_queue_push( &free_queue, &animations[ i ] );
    }
    // Start the animation timer.
    post_periodic( &layout_animate_callback, NULL, ANIMATION_PERIOD, ANIMATION_PERIOD );
}

/*
 *  layout_home() - splash home screen
 *
 *  INPUT - none
 *  OUTPUT - none
 */
void layout_home(void)
{
	layout_home_helper(false);
}

/*
 *  layout_home_reversed() - splash home screen in reverse
 *
 *  INPUT - none
 *  OUTPUT - none
 */
void layout_home_reversed(void)
{
	layout_home_helper(true);
}

/*
 *  layout_home_helper() - splash home screen helper
 *
 *  INPUT - true/false - reverse or normal
 *  OUTPUT - none
 */
static void layout_home_helper(bool reversed)
{
    layout_clear();

    static AnimationImageDrawableParams logo;
    logo.base.x = 100;
    logo.base.y = 10;

    if(reversed) {
    	logo.img_animation = get_logo_reversed_animation();
    } else {
    	logo.img_animation = get_logo_animation();
    }

    layout_add_animation(
		&layout_animate_images,
		(void*)&logo,
		get_image_animation_duration(logo.img_animation));

    while(is_animating()) {
		animate();
		display_refresh();
	}
}

/*
 *  layout_home_helper() - splash home screen helper
 *
 *  INPUT - true/false - reverse or normal
 *  OUTPUT - none
 */
void layout_screensaver(void)
{
    static AnimationImageDrawableParams screensaver;
    screensaver.base.x = 0;
    screensaver.base.y = 0;

    screensaver.img_animation = get_screensaver_animation();

    layout_add_animation(
		&layout_animate_images,
		(void*)&screensaver,
		0);
}

/*
 * layout_standard_notification() - display standard notification on LCD screen
 *
 * INPUT - 
 *      1. string pointer1
 *      2. string pointer2
 *      3. notification type
 * OUTPUT - 
 *      none
 */
void layout_standard_notification(const char* str1, const char* str2, NotificationType type)
{
	call_leaving_handler();
    layout_clear();

    DrawableParams sp;
    const Font* title_font = get_title_font();
    const Font* body_font = get_body_font();
    const uint32_t body_line_count = calc_str_line(body_font, str2, BODY_WIDTH);

    /* Determine vertical alignment and body width */
    sp.y = TOP_MARGIN;
    if(body_line_count == ONE_LINE) {
    	sp.y = TOP_MARGIN_FOR_ONE_LINE;
    } else if(body_line_count == TWO_LINES) {
    	sp.y = TOP_MARGIN_FOR_TWO_LINES;
    }

    /* Format Title */
    char upper_str1[TITLE_CHAR_MAX];
    strlcpy(upper_str1, str1, TITLE_CHAR_MAX);
    strupr(upper_str1);

    /* Title */
    sp.x = LEFT_MARGIN;
    sp.color = TITLE_COLOR;
    draw_string(canvas, title_font, upper_str1, &sp, TITLE_WIDTH, font_height(title_font));

    /* Body */
    sp.y += font_height(body_font) + BODY_TOP_MARGIN;
    sp.x = LEFT_MARGIN;
    sp.color = BODY_COLOR;
    draw_string(canvas, body_font, str2, &sp, BODY_WIDTH, font_height(body_font) + BODY_FONT_LINE_PADDING);

    layout_notification_icon(type, &sp);
}

/*
 * layout_transaction_notification() - display standard notification on LCD screen
 *
 * INPUT - 
 *      1. string pointer1
 *      2. string pointer2
 *      3. notification type
 * OUTPUT - 
 *      none
 */
void layout_transaction_notification(const char* amount, const char* address, NotificationType type)
{
    call_leaving_handler();
    layout_clear();

    DrawableParams sp;
    const Font* amount_font = get_title_font();
    const Font* address_font = get_title_font();

    /* Unbold fonts if address becomes too long */
    if(calc_str_width(address_font, address) > TRANSACTION_WIDTH) {
        amount_font = get_body_font();
        address_font = get_body_font();
    }

    /* Determine vertical alignment and body width */
    sp.y =  TOP_MARGIN_FOR_ONE_LINE;

    /* Format amount line */
    char title[BODY_CHAR_MAX];
    snprintf(title, BODY_CHAR_MAX, "Send %s to", amount);

    /* Draw amount */
    sp.x = LEFT_MARGIN;
    sp.color = TITLE_COLOR;
    draw_string(canvas, amount_font, title, &sp, TRANSACTION_WIDTH, font_height(amount_font));

    /* Draw address */
    sp.y += font_height(address_font) + TRANSACTION_TOP_MARGIN;
    sp.x = LEFT_MARGIN;
    sp.color = BODY_COLOR;
    draw_string(canvas, address_font, address, &sp, TRANSACTION_WIDTH, font_height(address_font) + BODY_FONT_LINE_PADDING);

    layout_notification_icon(type, &sp);
}

/*
 * layout_address_notification() - display address notification
 *
 * INPUT - 
 *      1. string pointer1
 *      2. address to display both as string and QR
 *      3. notification type
 * OUTPUT - 
 *      none
 */
void layout_address_notification(const char* desc, const char* address, NotificationType type)
{
    call_leaving_handler();
    layout_clear();

    DrawableParams sp;
    const Font* str1_font = get_title_font();
    const Font* address_font = get_title_font();

    /* Unbold fonts if address becomes too long */
    if(calc_str_width(address_font, address) > TRANSACTION_WIDTH) {
        address_font = get_body_font();
    }

    /* Determine vertical alignment and body width */
    sp.y =  TOP_MARGIN_FOR_ONE_LINE;

    /* Draw address */
    sp.y += font_height(address_font) + ADDRESS_TOP_MARGIN;
    sp.x = LEFT_MARGIN;
    sp.color = BODY_COLOR;
    draw_string(canvas, address_font, address, &sp, TRANSACTION_WIDTH, font_height(address_font) + BODY_FONT_LINE_PADDING);

    /* Draw description */
    if(strcmp(desc, "") != 0) {
        sp.y = TOP_MARGIN_FOR_ONE_LINE;
        sp.x = MULTISIG_LEFT_MARGIN;
        sp.color = BODY_COLOR;
        draw_string(canvas, address_font, desc, &sp, TRANSACTION_WIDTH, font_height(address_font) + BODY_FONT_LINE_PADDING);
    }

    layout_address(address);
    layout_notification_icon(type, &sp);
}

/*
 * layout_notification_icon() - display notification icon
 *
 * INPUT - 
 *      1. notification type
 *      2. drawable parameters for icon notification placement
 * OUTPUT - 
 *      none
 */
void layout_notification_icon(NotificationType type, DrawableParams *sp) {
    /* Determine animation/icon to show */
    static AnimationImageDrawableParams icon;
    switch(type){
        case NOTIFICATION_REQUEST:
            icon.base.x = 234;
            icon.base.y = 4;
            icon.img_animation = get_confirm_icon_animation();

            layout_add_animation(
                &layout_animate_images,
                (void*)&icon,
                get_image_animation_duration(icon.img_animation));
            break;
        case NOTIFICATION_REQUEST_NO_ANIMATION:
            sp->x = 234;
            sp->y = 4;
            draw_bitmap_mono_rle(canvas, sp, get_confirm_icon_image());
            break;
        case NOTIFICATION_CONFIRM_ANIMATION:
            icon.base.x = 232;
            icon.base.y = 2;
            icon.img_animation = get_confirming_animation();

            layout_add_animation(
                &layout_animate_images,
                (void*)&icon,
                get_image_animation_duration(icon.img_animation));
            break;
        case NOTIFICATION_CONFIRMED:
            sp->x = 232;
            sp->y = 2;
            draw_bitmap_mono_rle(canvas, sp, get_confirmed_image());
            break;
        case NOTIFICATION_UNPLUG:
            sp->x = 208;
            sp->y = 21;
            draw_bitmap_mono_rle(canvas, sp, get_unplug_image());
            break;
        case NOTIFICATION_RECOVERY:
            sp->x = 221;
            sp->y = 20;
            draw_bitmap_mono_rle(canvas, sp, get_recovery_image());
            break;
        case NOTIFICATION_INFO:
        default:
            /* no action requires */
            break;
    }
}

/*
 * layout_warning() - display warning message on display
 *
 * INPUT -
 * 		prompt - string to display
 * OUTPUT -
 */
void layout_warning(const char* str)
{
	call_leaving_handler();
    layout_clear();

    const Font* font = get_body_font();

    /* Title */
    DrawableParams sp;
    sp.x = (KEEPKEY_DISPLAY_WIDTH - calc_str_width(font, str)) / 2;
    sp.y = 50;
    sp.color = TITLE_COLOR;
    draw_string(canvas, font, str, &sp, KEEPKEY_DISPLAY_WIDTH, font_height(font));

    static AnimationImageDrawableParams warning;
    warning.img_animation = get_warning_animation();
    warning.base.y = 7;
    warning.base.x = 107;
    layout_add_animation( &layout_animate_images, (void*)&warning, 0);
}

/*
 * layout_simple_message() - displays a simple one line message
 *
 * INPUT - 
 * 		str - string to display
 * OUTPUT -
 */
void layout_simple_message(const char* str)
{
	call_leaving_handler();
    layout_clear();

    const Font* font = get_title_font();

    /* Format Message */
    char upper_str[TITLE_CHAR_MAX];
    strlcpy(upper_str, str, TITLE_CHAR_MAX);
    strupr(upper_str);

    /* Draw Message */
    DrawableParams sp;
    sp.x = (KEEPKEY_DISPLAY_WIDTH - calc_str_width(font, upper_str)) / 2;
    sp.y = (KEEPKEY_DISPLAY_HEIGHT / 2) - (font_height(font) / 2);
    sp.color = TITLE_COLOR;
    draw_string(canvas, font, upper_str, &sp, KEEPKEY_DISPLAY_WIDTH, font_height(font));
}

/*
 * layout_pin() - draw security pin layout on LCD screen
 *
 * INPUT - 
 *      1. pointer to string message 
 *      2. pointer PIN storage
 * OUTPUT - 
 *      none
 */
void layout_pin(const char* str, char pin[])
{
	DrawableParams sp;

	call_leaving_handler();
	layout_clear();

    /* Draw prompt */
	const Font* font = get_body_font();
    sp.y = 29;
    sp.x = (140 - calc_str_width(font, str)) / 2;
    sp.color = BODY_COLOR;
    draw_string(canvas, font, str, &sp, TITLE_WIDTH, font_height(font));
    display_refresh();

	/* Animate pin scrambling */
	layout_add_animation( &layout_animate_pin, (void*)pin, PIN_MAX_ANIMATION_MS);
}

void layout_cipher(const char* current_word, const char* cipher)
{
    DrawableParams sp;
    const Font* title_font = get_body_font();

    call_leaving_handler();
    layout_clear();

    /* Draw prompt */
    sp.y = 11;
    sp.x = 4;
    sp.color = BODY_COLOR;
    draw_string(canvas, title_font, "Recovery Cipher:", &sp, 58, font_height(title_font) + 3);
    display_refresh();

    /* Draw current word */
    sp.y = 46;
    sp.x = 4;
    sp.color = BODY_COLOR;
    draw_string(canvas, title_font, current_word, &sp, 68, font_height(title_font));
    display_refresh();

    /* Animate cipher */
    layout_add_animation(&layout_animate_cipher, (void*)cipher, CIPHER_ANIMATION_FREQUENCY_MS * 30);
}

/*
 * layout_loading() - load image for display
 *
 * INPUT - none
 * OUTPUT - none
 *
 */
void layout_loading()
{
    static AnimationImageDrawableParams loading_animation;

    call_leaving_handler();
    layout_clear();

    loading_animation.img_animation = get_loading_animation();
	loading_animation.base.x = 83;
	loading_animation.base.y = 29;
    layout_add_animation( &layout_animate_images, (void*)&loading_animation, 0);
    force_animation_start();
}

/*
 * layout_address() - draws qr code of address to oled
 *
 * INPUT - 
 *      1. pointer to string address
 * OUTPUT - 
 *      none
 */
void layout_address(const char* address) {
    static unsigned char bitdata[QR_MAX_BITDATA];

    int a, i, j;
    int side = qr_encode(QR_LEVEL_M, 0, address, 0, bitdata);

    if (side > 0 && side <= 29) {
        /* Draw QR background */
        draw_box_simple(canvas, 0xFF, QR_DISPLAY_X, QR_DISPLAY_Y, 
            (side + 2) * QR_DISPLAY_SCALE, (side + 2) * QR_DISPLAY_SCALE);

        /* Fill in QR */
        for (i = 0; i < side; i++) {
            for (j = 0; j< side; j++) {
                a = j * side + i;
                if (bitdata[a / 8] & (1 << (7 - a % 8))) {
                    draw_box_simple(canvas, 0x00, 
                        QR_DISPLAY_SCALE + (i + QR_DISPLAY_X) * QR_DISPLAY_SCALE,
                        QR_DISPLAY_SCALE + (j + QR_DISPLAY_Y) * QR_DISPLAY_SCALE,
                        QR_DISPLAY_SCALE, QR_DISPLAY_SCALE);
                }
            }
        }
    }
}

/*
 * animate() - image animation
 *
 * INPUT - none 
 * OUTPUT -none 
 */
void animate(void)
{
    if(animate_flag ) {
        Animation* animation = animation_queue_peek( &active_queue );

        while( animation != NULL ) {
            Animation* next = animation->next;

            animation->elapsed += ANIMATION_PERIOD;

            animation->animate_callback(
                animation->data,
                animation->duration,
                animation->elapsed );

            if( ( animation->duration > 0 ) && ( animation->elapsed >= animation->duration ) ) {
                animation_queue_push(
                    &free_queue,
                    animation_queue_get( &active_queue, animation->animate_callback ) );
            }

            animation = next;
        }

        animate_flag = false;
        }
}

/*
 * is_animating() - get animation status
 *
 * INPUT - none
 * OUTPUT - true/false
 */
bool is_animating(void)
{
	if(animation_queue_peek( &active_queue ) == NULL) {
		return false;
    } else {
		return true;
    }
}

/*
 * layout_animate_images() - animate image on display
 *
 * INPUT - 
 *      *data - pointer to image 
 *      duration - duration of the image animation
 *      elapsed - delay before drawing the image
 * OUTPUT - 
 *      none
 */
static void layout_animate_images(void* data, uint32_t duration, uint32_t elapsed)
{
	const Image* img;
	AnimationImageDrawableParams* animation_img_params = (AnimationImageDrawableParams*)data;

	if(duration == 0) {// looping
        img = get_image_animation_frame(animation_img_params->img_animation, elapsed, true);
    } else {
        img = get_image_animation_frame(animation_img_params->img_animation, elapsed, false);
    }
    if(img) {
        draw_bitmap_mono_rle(canvas, &animation_img_params->base, img);
    }
}

/*
 * layout_animate_pin() - animate pin scramble
 *
 * INPUT -
 *      *data - pointer to pin array
 *      duration - duration of the pin scramble animation
 *      elapsed - how long we have animating
 * OUTPUT -
 *      none
 */
static void layout_animate_pin(void* data, uint32_t duration, uint32_t elapsed)
{
	BoxDrawableParams box_params = {{0x00, 0, 0}, 64, 256};
	DrawableParams sp;
	char *pin = (char*)data;
	uint8_t color_stepping[] = {PIN_MATRIX_STEP1, PIN_MATRIX_STEP2, PIN_MATRIX_STEP3, PIN_MATRIX_STEP4, PIN_MATRIX_FOREGROUND};

	const Font* pin_font = get_pin_font();

	PINAnimationConfig *cur_pos_cfg;
	uint8_t cur_pos;
	uint32_t cur_pos_elapsed;

    /* Draw matrix */
    box_params.base.color = PIN_MATRIX_BACKGROUND;
    for(uint8_t row = 0; row < 3; row++) {
        for(uint8_t col = 0; col < 3; col++) {
            box_params.base.y = 5 + row * 19;
            box_params.base.x = 140 + col * 19;
            box_params.height = 18;
            box_params.width = 18;
            draw_box(canvas, &box_params);
        }
    }

	/* Configure each PIN digit animation settings */
	PINAnimationConfig pin_animation_cfg[] = {
			{SLIDE_RIGHT, 8 * PIN_SLIDE_DELAY}, // 1
			{SLIDE_UP, 7 * PIN_SLIDE_DELAY}, 	// 2
			{SLIDE_DOWN, 6 * PIN_SLIDE_DELAY}, 	// 3
			{SLIDE_LEFT, 5 * PIN_SLIDE_DELAY}, 	// 4
			{SLIDE_UP, 4 * PIN_SLIDE_DELAY}, 	// 5
			{SLIDE_RIGHT, 3 * PIN_SLIDE_DELAY}, // 6
			{SLIDE_UP, 0 * PIN_SLIDE_DELAY}, 	// 7
			{SLIDE_RIGHT, 1 * PIN_SLIDE_DELAY}, // 8
			{SLIDE_DOWN, 2 * PIN_SLIDE_DELAY}  	// 9
	};

	/* Draw each pin digit individually base on animation config on matrix position */
	for(uint8_t row = 0; row < 3; row++) {
		for(uint8_t col = 0; col < 3; col++) {

			cur_pos = col + (2 - row) * 3;
			cur_pos_cfg = &pin_animation_cfg[cur_pos];
			cur_pos_elapsed = elapsed - cur_pos_cfg->elapsed_start_ms;

			/* Skip position is enough time has not passed */
			if(cur_pos_cfg->elapsed_start_ms > elapsed) {
				continue;
			}

			/* Determine color */
			sp.color = PIN_MATRIX_FOREGROUND;
			for(uint8_t color_index = 0; color_index < sizeof(color_stepping)/sizeof(color_stepping[0]); color_index++) {
				if(cur_pos_elapsed < (color_index * PIN_MATRIX_ANIMATION_FREQUENCY_MS)) {
					sp.color = color_stepping[color_index];
					break;
				}
			}

			uint8_t pad = 7;

			/* Adjust pad */
			if(pin[cur_pos] == '1') {
				pad++;
            }

			sp.y = 8 + row * 19;
			sp.x = 138 + pad + col * 19;

			uint8_t adj_pos = cur_pos_elapsed / 40;
			if(adj_pos <= 5) {
				adj_pos = 5 - adj_pos;
				switch(cur_pos_cfg->direction) {
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
    draw_box_simple(canvas, MATRIX_MASK_COLOR, 137, 2, PIN_MATRIX_GRID_SIZE * 3 + 8, MATRIX_MASK_MARGIN);
    draw_box_simple(canvas, MATRIX_MASK_COLOR, 137, 5 + PIN_MATRIX_GRID_SIZE, PIN_MATRIX_GRID_SIZE * 3 + 8, 1);
    draw_box_simple(canvas, MATRIX_MASK_COLOR, 137, 6 + PIN_MATRIX_GRID_SIZE * 2, PIN_MATRIX_GRID_SIZE * 3 + 8, 1);
    draw_box_simple(canvas, MATRIX_MASK_COLOR, 137, 7 + PIN_MATRIX_GRID_SIZE * 3, PIN_MATRIX_GRID_SIZE * 3 + 8, MATRIX_MASK_MARGIN);

    /* Mask vertically */
    draw_box_simple(canvas, MATRIX_MASK_COLOR, 137, 2, MATRIX_MASK_MARGIN, 18 * 3 + 8);
    draw_box_simple(canvas, MATRIX_MASK_COLOR, 140 + PIN_MATRIX_GRID_SIZE, 2, 1, PIN_MATRIX_GRID_SIZE * 3 + 8);
    draw_box_simple(canvas, MATRIX_MASK_COLOR, 141 + PIN_MATRIX_GRID_SIZE * 2, 2, 1, PIN_MATRIX_GRID_SIZE * 3 + 8);
    draw_box_simple(canvas, MATRIX_MASK_COLOR, 142 + PIN_MATRIX_GRID_SIZE * 3, 2, MATRIX_MASK_MARGIN, PIN_MATRIX_GRID_SIZE * 3 + 8);
}

/*
 * layout_animate_cipher() - animate recovery cipher
 *
 * INPUT -
 *      *data - pointer to pin array
 *      duration - duration of the pin scramble animation
 *      elapsed - how long we have animating
 * OUTPUT -
 *      none
 */
static void layout_animate_cipher(void* data, uint32_t duration, uint32_t elapsed)
{
    int row, letter, x_padding, cur_pos_elapsed, adj_pos, adj_x, adj_y, cur_index;
    uint8_t color_stepping[] = {CIPHER_STEP_1, CIPHER_STEP_2, CIPHER_STEP_3, CIPHER_STEP_4, CIPHER_FOREGROUND};
    char *cipher = (char*)data;
    char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
    char *current_letter = alphabet;

    DrawableParams sp;
    const Font* title_font = get_title_font();
    const Font* cipher_font = get_body_font();

    /* Clear area behind cipher */
    draw_box_simple(canvas, CIPHER_MASK_COLOR, CIPHER_START_X, 0, KEEPKEY_DISPLAY_WIDTH-CIPHER_START_X, KEEPKEY_DISPLAY_HEIGHT);

    /* Draw grid */
    sp.y = CIPHER_START_Y;
    sp.x = CIPHER_START_X;
    for(row = 0; row < CIPHER_ROWS; row++) {
        for(letter = 0; letter < CIPHER_LETTER_BY_ROW; letter++) {
            cur_index = (row * CIPHER_LETTER_BY_ROW) + letter;
            cur_pos_elapsed = elapsed - cur_index * CIPHER_ANIMATION_FREQUENCY_MS;
            sp.x = CIPHER_START_X + (letter * (CIPHER_GRID_SIZE + CIPHER_GRID_SPACING));
            x_padding = 0;

            /* Draw grid */
            draw_box_simple(canvas, CIPHER_STEP_1, sp.x - 4, sp.y + CIPHER_GRID_SIZE, CIPHER_GRID_SIZE, CIPHER_GRID_SIZE);

            x_padding = 0;
            if(*current_letter == 'i' || *current_letter == 'l') {
                x_padding = 2;
            } else if(*current_letter == 'm' || *current_letter == 'w') {
                x_padding = -1;
            }

            /* Draw map */
            draw_char_simple(canvas, title_font, *current_letter++, CIPHER_MAP_FONT_COLOR, sp.x + x_padding, sp.y);

            x_padding = 0;
            if(*cipher == 'i' || *cipher == 'l') {
                x_padding = 2;
            } else if(*cipher == 'k' || *cipher == 'j' ||
                    *cipher == 'r' || *cipher == 'f') {
                x_padding = 1;
            } else if(*cipher == 'm' || *cipher == 'w') {
                x_padding = -1;
            }

            /* Draw cipher */
            if(cur_pos_elapsed > 0) {
                adj_pos = cur_pos_elapsed / CIPHER_ANIMATION_FREQUENCY_MS;

                adj_x = 0;
                adj_y = 0;

                if(adj_pos < 5){
                    if(cur_index % 4 == 0) {
                        adj_y = -(5 - adj_pos);
                    } else if (cur_index % 4 == 1) {
                        adj_x = 5 - adj_pos;
                    } else if (cur_index % 4 == 2) {
                        adj_y = 5 - adj_pos;
                    } else {                    
                        adj_x = -(5 - adj_pos);
                    }
                }

                draw_char_simple(canvas, cipher_font, *cipher, CIPHER_FONT_COLOR, 
                    sp.x + x_padding + adj_x, sp.y + (CIPHER_GRID_SIZE + CIPHER_GRID_SPACING) + adj_y);
            }

            /* Draw grid mask between boxes */
            draw_box_simple(canvas, CIPHER_MASK_COLOR, sp.x - 5, sp.y + CIPHER_GRID_SIZE, 1, CIPHER_GRID_SIZE);

            *cipher++;
        }
        sp.x = CIPHER_START_X;
        sp.y += 31;
    }

    /* Draw mask */
    draw_box_simple(canvas, CIPHER_MASK_COLOR, CIPHER_START_X - 4, 14, CIPHER_HORIZONTAL_MASK_WIDTH, 
        CIPHER_HORIZONTAL_MASK_HEIGHT_2);
    draw_box_simple(canvas, CIPHER_MASK_COLOR, CIPHER_START_X - 4, 45, CIPHER_HORIZONTAL_MASK_WIDTH, 
        CIPHER_HORIZONTAL_MASK_HEIGHT_2);
    draw_box_simple(canvas, CIPHER_MASK_COLOR, CIPHER_START_X - 4, 29, CIPHER_HORIZONTAL_MASK_WIDTH, 
        CIPHER_HORIZONTAL_MASK_HEIGHT_3);
    draw_box_simple(canvas, CIPHER_MASK_COLOR, CIPHER_START_X - 4, 59, CIPHER_HORIZONTAL_MASK_WIDTH, 
        CIPHER_HORIZONTAL_MASK_HEIGHT_4);
    draw_box_simple(canvas, CIPHER_MASK_COLOR, KEEPKEY_DISPLAY_WIDTH - CIPHER_HORIZONTAL_MASK_WIDTH_3, 0,
        CIPHER_HORIZONTAL_MASK_WIDTH_3, KEEPKEY_DISPLAY_HEIGHT);
}

/*
 * layout_clear() - API to clear display
 *
 * INPUT - none
 * OUTPUT - none
 */
void layout_clear(void)
{
    layout_clear_animations();

    layout_clear_static();

}

/*
 * layout_clear_static() - clear display 
 *
 * INPUT - none
 * OUTPUT - none
 */
void layout_clear_static(void)
{
    BoxDrawableParams bp;
    bp.width = canvas->width;
    bp.height = canvas->height;
    bp.base.x = 0;
    bp.base.y = 0;
    bp.base.color = 0x00;

    draw_box( canvas, &bp );
}

/*
 * layout_animate_callback() - callback function to set animation flag   
 *
 * INPUT - 
 *      *context - not used 
 * OUTPUT -
		none
 */
static void layout_animate_callback(void *context)
{
    (void)context;
    animate_flag = true;
}

/*
 * force_animation_start() - direct call to start animation 
 *
 * INPUT - none
 * OUTPUT - none
 */
void force_animation_start(void)
{
    animate_flag = true;
}

/*
 * animating_progress_handler() - animate storage update progress
 *
 * INPUT - none
 * OUTPUT - none
 */
void animating_progress_handler(void)
{
	if(is_animating()) {
		animate();
		display_refresh();
	}
}

/*
 * layout_add_animation() - queue up the animation in active_queue. 
 *
 * INPUT -
 *      callback - animation callback function
 *      *data - pointer to image 
 *      duration - duration of animation 
 * OUTPUT - 
 *      none
 */
void layout_add_animation(AnimateCallback callback, void *data, uint32_t duration)
{
    Animation* animation = animation_queue_get( &active_queue, callback );

    if( animation == NULL ) {
        animation = animation_queue_pop( &free_queue );
    }
    animation->data = data;
    animation->duration = duration;
    animation->elapsed = 0;
    animation->animate_callback = callback;
    animation_queue_push( &active_queue, animation );
}

#if defined(AGGRO_UNDEFINED_FN)
/*
 * layout_remove_animation() - remove animation node that contains the callback function from the queue
 *
 * INPUT - 
 *      callback - animation callback function
 * OUTPUT - 
		none
 */ 
static void layout_remove_animation(AnimateCallback callback)
{
    Animation* animation = animation_queue_get( &active_queue, callback );

    if( animation != NULL ) {
        animation_queue_push( &free_queue, animation );
    }
}
#endif

/*
 * layout_clear_animations() - clear all animation from queue
 *
 * INPUT - none
 * OUTPUT - none
 */
void layout_clear_animations(void)
{
    Animation* animation = animation_queue_pop( &active_queue );

    while( animation != NULL ) {
        animation_queue_push( &free_queue, animation );
        animation = animation_queue_pop( &active_queue );
    }
}

/*
 * animation_queue_peek() - get current animation node in head pointer
 *
 * INPUT -
 *      *queue - pointer to animation queue
 * OUTPUT - 
 *      node pointed to by head pointer
 */ 
static Animation* animation_queue_peek(AnimationQueue* queue)
{
    return queue->head;
}

/* 
 * animation_queue_push() - push animation into queue
 *
 * INPUT - 
 *      *queue - pointer to animation queue
 * OUTPUT - 
 *      none
 */
static void animation_queue_push(AnimationQueue* queue, Animation* node)
{
    if( queue->head != NULL ) {
        node->next = queue->head;
    } else {
        node->next = NULL;
    }
 
    queue->head = node;
    queue->size += 1;
}


/* 
 * animation_queue_pop() - pop a node from animation queue
 *
 * INPUT - 
 *      *queue - pointer to animation queue
 * OUTPUT -
 *      pointer to a node from the queue
 */
static Animation* animation_queue_pop(AnimationQueue* queue)
{
    Animation* animation = queue->head;

    if( animation != NULL ) {
        queue->head = animation->next;
        queue->size -= 1;
    }
    return(animation);
}

/*
 * animation_queue_get() - get a queue containg the callback function 
 *
 * INPUT - 
 *      *queue - pointer to animation queue
 *      callback - animation callback function
 * OUTPUT - 
 *      pointer to Animation node
 */
static Animation* animation_queue_get(AnimationQueue* queue, AnimateCallback callback)
{
    Animation* current = queue->head;
    Animation* result = NULL;

    if( current != NULL ) {
        if( current->animate_callback == callback ) {
            result = current;
            queue->head = current->next;
        } else {
            Animation* previous = current;
            current = current->next;

            while( ( current != NULL ) && ( result == NULL ) ) {
                // Found the node!
                if( current->animate_callback == callback ) {
                    result = current;
                    previous->next = current->next;
                    result->next = NULL;
                }

                previous = current;
                current = current->next;
            }
        }
    }
    if( result != NULL ) {
        queue->size -= 1;
    }

    return(result);
}

/*
 * set_leaving_handler() - setup leaving handler
 *
 * INPUT -
 *      leaving_func - leaving handler to be set
 * OUTPUT -
 *      none
 */
void set_leaving_handler(leaving_handler_t leaving_func)
{
	leaving_handler = leaving_func;
}

/*
 * call_leaving_handler() - call leaving handler
 *
 * INPUT -
 *      none
 * OUTPUT -
 * 		none
 */
static void call_leaving_handler(void)
{
	if(leaving_handler)
		(*leaving_handler)();
}

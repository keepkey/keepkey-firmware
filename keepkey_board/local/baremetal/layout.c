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

    const Font* title_font = get_title_font();
    const Font* body_font = get_body_font();

    /* Format Title */
    char upper_str1[title_char_width()];
    strcpy(upper_str1, str1);
    strupr(upper_str1);

    /* Title */
    DrawableParams sp;
    sp.y = TOP_MARGIN - 4;
    sp.x = LEFT_MARGIN;
    sp.color = TITLE_COLOR;
    draw_string(canvas, title_font, upper_str1, &sp, TITLE_WIDTH, font_height(title_font));

    /* Body */
    sp.y += font_height(body_font) + 2;
    sp.x = LEFT_MARGIN;
    sp.color = BODY_COLOR;
    draw_string(canvas, body_font, str2, &sp, BODY_WIDTH, font_height(body_font) + 1);



    /* Confirm text */
    sp.y = 46;
	sp.x = 215;
	sp.color = 0x66;

    /* Determine animation/icon to show */
    static AnimationImageDrawableParams icon;
    switch(type){
    	case NOTIFICATION_REQUEST:
    		icon.base.x = 211;
			icon.base.y = 0;
			icon.img_animation = get_confirm_icon_animation();

			draw_string(canvas, body_font, "confirm", &sp, BODY_WIDTH, font_height(body_font) + 1);

			layout_add_animation(
				&layout_animate_images,
				(void*)&icon,
				0);
			break;
		case NOTIFICATION_CONFIRM_ANIMATION:
			icon.base.x = 217;
			icon.base.y = 13;
			icon.img_animation = get_confirming_animation();

			draw_string(canvas, body_font, "confirm", &sp, BODY_WIDTH, font_height(body_font) + 1);

			layout_add_animation(
				&layout_animate_images,
				(void*)&icon,
				get_image_animation_duration(icon.img_animation));
			break;
		case NOTIFICATION_CONFIRMED:
			sp.x = 226;
			draw_string(canvas, body_font, "ok!", &sp, BODY_WIDTH, font_height(body_font) + 1);

			sp.x = 217;
			sp.y = 13;
			draw_bitmap_mono_rle(canvas, &sp, get_confirmed_image());
			break;
		case NOTIFICATION_UNPLUG:
			sp.x = 208;
			sp.y = 21;
			draw_bitmap_mono_rle(canvas, &sp, get_unplug_image());
			break;
		case NOTIFICATION_RECOVERY:
			sp.x = 221;
			sp.y = 20;
			draw_bitmap_mono_rle(canvas, &sp, get_recovery_image());
			break;
		case NOTIFICATION_INFO:
		default:
			/* no action requires */
			break;
    }
}

/*
 * layout_warning() - display warning message on LCD screen
 *
 * INPUT - 
 * OUTPUT -
 */
void layout_warning(const char* prompt)
{
	call_leaving_handler();
    layout_clear();

    const Font* font = get_title_font();

    /* Format Title */
    char upper_prompt[warning_char_width()];
    strcpy(upper_prompt, "WARNING: ");
    strcat(upper_prompt, prompt);
    strupr(upper_prompt);

    /* Title */
    DrawableParams sp;
    sp.x = (256 - calc_str_width(font, upper_prompt)) / 2;
    sp.y = 47;
    sp.color = TITLE_COLOR;
    draw_string(canvas, font, upper_prompt, &sp, WARNING_WIDTH, font_height(font));

    static AnimationImageDrawableParams warning;
    warning.img_animation = get_warning_animation();
    warning.base.y = 7;
    warning.base.x = 107;
    layout_add_animation( &layout_animate_images, (void*)&warning, 0);
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
void layout_pin(const char* prompt, char pin[])
{
	DrawableParams sp;

	call_leaving_handler();
	layout_clear();

	/* Format prompt */
	char upper_prompt[title_char_width()];
	strcpy(upper_prompt, prompt);
	strupr(upper_prompt);

    /* Draw prompt */
	const Font* font = get_title_font();
    sp.y = 24;
    sp.x = (100 - calc_str_width(font, upper_prompt)) / 2;
    sp.color = 0x55;
    draw_string(canvas, font, upper_prompt, &sp, TITLE_WIDTH, font_height(font));
    display_refresh();

	/* Animate pin scrambling */
	layout_add_animation( &layout_animate_pin, (void*)pin, 0);
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

    layout_clear();

    loading_animation.img_animation = get_loading_animation();
	loading_animation.base.x = 83;
	loading_animation.base.y = 29;
    layout_add_animation( &layout_animate_images, (void*)&loading_animation, 0);
    force_animation_start();
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
	char pin_num[] = {0, 0};

	PINAnimationConfig *cur_pos_cfg;
	uint8_t cur_pos;
	uint32_t cur_pos_elapsed;

	/* Init temp canvas and make sure it is cleared */
	static uint8_t tmp_canvas_buffer[ KEEPKEY_DISPLAY_HEIGHT * KEEPKEY_DISPLAY_WIDTH ];
	Canvas tmp_canvas;
	tmp_canvas.buffer = tmp_canvas_buffer;
	tmp_canvas.width = KEEPKEY_DISPLAY_WIDTH;
	tmp_canvas.height = KEEPKEY_DISPLAY_HEIGHT;
	draw_box(&tmp_canvas, &box_params);

	/* Configure each PIN digit animation settings */
	PINAnimationConfig pin_animation_cfg[] = {
			{SLIDE_RIGHT, 160}, // 1
			{SLIDE_UP, 140}, 	// 2
			{SLIDE_DOWN, 120}, 	// 3
			{SLIDE_LEFT, 100}, 	// 4
			{SLIDE_UP, 80}, 	// 5
			{SLIDE_RIGHT, 60}, 	// 6
			{SLIDE_UP, 0}, 		// 7
			{SLIDE_RIGHT, 20}, 	// 8
			{SLIDE_DOWN, 40}  	// 9
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
			pin_num[0] = pin[cur_pos];

			/* Adjust pad */
			if(pin_num[0] == '4' || pin_num[0] == '6' || pin_num[0] == '8' || pin_num[0] == '9')
				pad--;

			sp.y = 9 + row * 17;
			sp.x = 99 + pad + col * 20;

			/* Determine position */
			for(uint8_t adj_pos = 0; adj_pos < 5; adj_pos++) {

				if(cur_pos_elapsed < ((5 - adj_pos) * PIN_MATRIX_ANIMATION_FREQUENCY_MS)) {
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
			}

			draw_string(&tmp_canvas, pin_font, pin_num, &sp, WARNING_WIDTH, font_height(pin_font));
		}
    }

	/* Draw matrix */
	box_params.base.color = PIN_MATRIX_BACKGROUND;
	for(uint8_t row = 0; row < 3; row++) {
		for(uint8_t col = 0; col < 3; col++) {
			box_params.base.y = 8 + row * 17;
			box_params.base.x = 100 + col * 20;
			box_params.height = 16;
			box_params.width = 19;
			draw_box(canvas, &box_params);

			/* Copy contents of box in tmp canvas over to real canvas */
			copy_box(canvas, &tmp_canvas, &box_params);
		}
	}
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
 * layout_char_width() - get display with respect to font type
 * 
 * INPUT -
 *      *font - pointer font type
 * OUTPUT - get display width 
 */
uint32_t layout_char_width(Font *font)
{
    return(KEEPKEY_DISPLAY_WIDTH / font_width(font));
}

/*
 * title_char_width() - get display titile width 
 *
 * INPUT - none 
 * OUTPUT - get title width
 */
uint32_t title_char_width()
{
	const Font* font = get_title_font();
    return((TITLE_WIDTH / font_width(font)) * TITLE_ROWS);
}

/*
 * body_char_width() - get display body width
 *
 * INPUT - none 
 * OUTPUT - get body width 
 */
uint32_t body_char_width()
{
	const Font* font = get_body_font();
    return((BODY_WIDTH / font_width(font)) * BODY_ROWS);
}

/*
 * warning_char_width() - get display warning width
 *
 * INPUT - none 
 * OUTPUT - get warning width 
 */
uint32_t warning_char_width()
{
	const Font* font = get_title_font();
    return((WARNING_WIDTH / font_width(font)) * WARNING_ROWS);
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

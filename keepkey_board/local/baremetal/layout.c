/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file layout.c
/// Provide functionality behind laying out the display.
///


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


//====================== CONSTANTS, TYPES, AND MACROS =========================

typedef void (*AnimateCallback)(void* data, uint32_t duration, uint32_t elapsed );

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

//=============================== VARIABLES ===================================


#define MAX_ANIMATIONS 5


//-----------------------------------------------------------------------------
// Configuration variables.
//
static const uint32_t ANIMATION_PERIOD = 20; // ms

/*
 * Margin
 */
static const uint32_t TOP_MARGIN  = 7;
static const uint32_t LEFT_MARGIN  = 4;

/*
 * Title
 */
static const uint8_t TITLE_COLOR = 0xFF;
static const uint32_t TITLE_WIDTH = 179;
static const uint32_t TITLE_ROWS = 1;
static const uint32_t TITLE_FONT_LINE_PADDING = 0;

/*
 * Body
 */
static const uint8_t BODY_COLOR = 0xFF;
static const uint32_t BODY_WIDTH = 206;
static const uint32_t BODY_ROWS = 3;
static const uint32_t BODY_FONT_LINE_PADDING = 2;

/*
 * Default Layout
 */
static const uint32_t NO_WIDTH = 0;

static const char* AMOUNT_LABEL_TEXT    = "Amount:";
static const char* ADDRESS_LABEL_TEXT   = "Address:";
static const char* CONFIRM_LABEL_TEXT   = "Confirming transaction...";


//-----------------------------------------------------------------------------
// Operation variables. 
static AnimationQueue active_queue = { NULL, 0 };
static AnimationQueue free_queue = { NULL, 0 };

static Animation animations[ MAX_ANIMATIONS ];

static Canvas* canvas = NULL;

static volatile bool animate_flag = false;

/*
 * Standard time to wait for the confirmation.
 */
static const uint32_t STANDARD_CONFIRM_MS = 2000; 


//====================== PRIVATE FUNCTION DECLARATIONS ========================


//-----------------------------------------------------------------------------
// 
static void
layout_animate(
        void* context 
);


//-----------------------------------------------------------------------------
// 
#if defined(AGGRO_UNDEFINED_FN)
static void
layout_remove_animation(
        AnimateCallback  callback
);  
#endif


//-----------------------------------------------------------------------------
// 
static void
animation_queue_push(
        AnimationQueue* queue,
        Animation*      node
);


//-----------------------------------------------------------------------------
// 
static Animation*
animation_queue_pop(
        AnimationQueue* queue
);



//-----------------------------------------------------------------------------
// 
static Animation*
animation_queue_peek(
        AnimationQueue* queue
);


//-----------------------------------------------------------------------------
// 
static Animation*
animation_queue_get(
        AnimationQueue* queue,
        AnimateCallback callback
);


//-----------------------------------------------------------------------------
// 
static void layout_animate_confirming(void* data, uint32_t duration, uint32_t elapsed);
static void layout_animate_images(void* data, uint32_t duration, uint32_t elapsed);


//=============================== FUNCTIONS ===================================


//-----------------------------------------------------------------------------
// See layout.h for public interface.
//
void layout_init(Canvas* new_canvas)
{
    canvas = new_canvas;

    int i;
    for( i = 0; i < MAX_ANIMATIONS; i++ )
    {
        animation_queue_push( &free_queue, &animations[ i ] );
    }

    // Start the animation timer.
    post_periodic( 
            &layout_animate,
            NULL,
            ANIMATION_PERIOD,
            ANIMATION_PERIOD );
}


//-----------------------------------------------------------------------------
// See layout.h for public interface.
//
void layout_home(void)
{    
    layout_clear();

    DrawableParams sp;
    sp.x = 0;
    sp.y = 0;

    draw_bitmap_mono_rle(canvas, &sp, get_home_image());
}


void layout_sleep(void)
{
    layout_clear();
}

void layout_standard_notification(const char* str1, const char* str2, NotificationType type)
{
    layout_clear();

    const Font* title_font = get_title_font();
    const Font* body_font = get_body_font();

    /*
     * Format Title
     */
    char upper_str1[title_char_width()];
    strcpy(upper_str1, str1);
    strupr(upper_str1);

    /*
     * Title
     */
    DrawableParams sp;
    sp.y = TOP_MARGIN - 4;
    sp.x = LEFT_MARGIN;
    sp.color = TITLE_COLOR;
    draw_string(canvas, title_font, upper_str1, &sp, TITLE_WIDTH, font_height(title_font));

    /*
     * Body
     */
    sp.y += font_height(body_font) + 2;
    sp.x = LEFT_MARGIN;
    sp.color = BODY_COLOR;
    draw_string(canvas, body_font, str2, &sp, BODY_WIDTH, font_height(body_font) + 1);

    /*
     * Determine animation/icon to show
     */
    static AnimationImageDrawableParams icon;
    switch(type){
    	case NOTIFICATION_REQUEST:
    		icon.base.x = 213;
			icon.base.y = 13;
			icon.img_animation = get_confirm_icon_animation();

			layout_add_animation(
				&layout_animate_images,
				(void*)&icon,
				0);
			break;
		case NOTIFICATION_CONFIRM_ANIMATION:
			icon.base.x = 220;
			icon.base.y = 19;
			icon.img_animation = get_confirming_animation();

			layout_add_animation(
				&layout_animate_images,
				(void*)&icon,
				get_image_animation_duration(icon.img_animation));
			break;
		case NOTIFICATION_CONFIRMED:
			sp.x = 220;
			sp.y = 19;
			draw_bitmap_mono_rle(canvas, &sp, get_confirmed_image());
			break;
    }
}

void layout_intro()
{
    static AnimationImageDrawableParams intro_animation;
    intro_animation.base.x = 0;
    intro_animation.base.y = 0;
    intro_animation.img_animation = get_boot_animation();

	layout_add_animation(
		&layout_animate_images,
		(void*)&intro_animation,
		get_image_animation_duration(intro_animation.img_animation));
}

void layout_loading(AnimationResource type)
{
    static AnimationImageDrawableParams loading_animation;

    /*
     * Background params
     */
    DrawableParams sp;
	sp.x = 0;
	sp.y = 0;

    switch(type){
    	case WIPE_ANIM:
    		loading_animation.img_animation = get_wipe_animation();
    		draw_bitmap_mono_rle(canvas, &sp, get_wipe_background_image());
    		loading_animation.base.x = 24;
    		loading_animation.base.y = 13;
    		break;
    	case SAVING_ANIM:
			loading_animation.img_animation = get_saving_animation();
			draw_bitmap_mono_rle(canvas, &sp, get_saving_background_image());
			loading_animation.base.x = 18;
			loading_animation.base.y = 9;
			break;
    }

    layout_add_animation(
		&layout_animate_images,
		(void*)&loading_animation,
		0);
}

//-----------------------------------------------------------------------------
// 
void animate(void)
{
    if( !animate_flag )
    {
        return;
    }

    Animation* animation = animation_queue_peek( &active_queue );

    while( animation != NULL )
    {
        Animation* next = animation->next;

        animation->elapsed += ANIMATION_PERIOD;

        animation->animate_callback(
                animation->data,
                animation->duration,
                animation->elapsed );

        if( ( animation->duration > 0 ) && ( animation->elapsed >= animation->duration ) )
        {
            animation_queue_push(
                    &free_queue,
                    animation_queue_get( &active_queue, animation->animate_callback ) );
        }

        animation = next;
    }

    animate_flag = false;
}

//-----------------------------------------------------------------------------
//
bool is_animating(void)
{
	if(animation_queue_peek( &active_queue ) == NULL)
		return false;
	else
		return true;
}

//-----------------------------------------------------------------------------
// See layout.h for public interface.
//
static void layout_animate_images(void* data, uint32_t duration, uint32_t elapsed)
{
	const Image* img;
	AnimationImageDrawableParams* animation_img_params = (AnimationImageDrawableParams*)data;

	if(duration == 0) // looping
		img = get_image_animation_frame(animation_img_params->img_animation, elapsed, true);
	else
		img = get_image_animation_frame(animation_img_params->img_animation, elapsed, false);

    if(img)
    	draw_bitmap_mono_rle(canvas, &animation_img_params->base, img);
}


//-----------------------------------------------------------------------------
// See layout.h for public interface.
//
void layout_clear(void)
{
    layout_clear_animations();

    layout_clear_static();

}

//-----------------------------------------------------------------------------
// See layout.h for public interface.
//
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


//-----------------------------------------------------------------------------
// 
static void layout_animate(void* context)
{
    (void)context;

    animate_flag = true;
}


//-----------------------------------------------------------------------------
//
void force_animation_start()
{
    animate_flag = true;
}


//-----------------------------------------------------------------------------
// 
void layout_add_animation(AnimateCallback callback, void* data, uint32_t duration)
{
    Animation* animation = animation_queue_get( &active_queue, callback );

    if( animation == NULL )
    {
        animation = animation_queue_pop( &free_queue );
    }

    animation->data = data;
    animation->duration = duration;
    animation->elapsed = 0;
    animation->animate_callback = callback;

    animation_queue_push( &active_queue, animation );
}


//-----------------------------------------------------------------------------
// 
#if defined(AGGRO_UNDEFINED_FN)
static void layout_remove_animation(AnimateCallback callback)
{
    Animation* animation = animation_queue_get( &active_queue, callback );

    if( animation != NULL )
    {
        animation_queue_push( &free_queue, animation );
    }
}
#endif


//-----------------------------------------------------------------------------
// 
void layout_clear_animations(void)
{
    Animation* animation = animation_queue_pop( &active_queue );

    while( animation != NULL )
    {
        animation_queue_push(
                &free_queue,
                animation );

        animation = animation_queue_pop( &active_queue );
    }
}


//-----------------------------------------------------------------------------
// 
static Animation* animation_queue_peek(AnimationQueue* queue)
{
    return queue->head;
}


//-----------------------------------------------------------------------------
// 
static void animation_queue_push(AnimationQueue* queue, Animation* node)
{
    if( queue->head != NULL )
    {
        node->next = queue->head;
    }
    else
    {
        node->next = NULL;
    }
 
    queue->head = node;
    queue->size += 1;
}


//-----------------------------------------------------------------------------
// 
static Animation* animation_queue_pop(AnimationQueue* queue)
{
    Animation* animation = queue->head;

    if( animation != NULL )
    {
        queue->head = animation->next;
        queue->size -= 1;
    }

    return animation;
}


//-----------------------------------------------------------------------------
// 
static Animation* animation_queue_get(AnimationQueue* queue, AnimateCallback callback)
{
    Animation* current = queue->head;
    Animation* result = NULL;

    if( current != NULL )
    {
        if( current->animate_callback == callback )
        {
            result = current;
            queue->head = current->next;
        }
        else
        {
            Animation* previous = current;
            current = current->next;

            while( ( current != NULL ) && ( result == NULL ) )
            {
                // Found the node!
                if( current->animate_callback == callback )
                {
                    result = current;
                    previous->next = current->next;
                    result->next = NULL;
                }

                previous = current;
                current = current->next;
            }
        }
    }

    if( result != NULL )
    {
        queue->size -= 1;
    }

    return result;
}

uint32_t layout_char_width(Font *font)
{
    return KEEPKEY_DISPLAY_WIDTH / font_width(font);
}

uint32_t title_char_width()
{
	const Font* font = get_title_font();
    return (TITLE_WIDTH / font_width(font)) * TITLE_ROWS;
}

uint32_t body_char_width()
{
	const Font* font = get_body_font();
    return (BODY_WIDTH / font_width(font)) * BODY_ROWS;
}

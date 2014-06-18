/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file layout.c
/// Provide functionality behind laying out the display.
///


//================================ INCLUDES ===================================


#include <stddef.h>
#include <stdio.h>

#include "draw.h"
#include "font.h"
#include "keepkey_leds.h"
#include "layout.h"
#include "timer.h"


//====================== CONSTANTS, TYPES, AND MACROS =========================

typedef void (*AnimateCallback)(void* data, uint32_t duration, uint32_t ellapsed );

typedef struct Animation Animation;
struct Animation
{
    uint32_t        duration;
    uint32_t        ellapsed;
 
    void*           data;
    AnimateCallback animate_callback;

    Animation*      next;
};


typedef struct
{
    Animation*  head;
    int         size;

} AnimationQueue;

#define SATOSHI_PER_BTC 1000000


//=============================== VARIABLES ===================================


#define MAX_ANIMATIONS 5


//-----------------------------------------------------------------------------
// Configuration variables.
//
static const uint32_t ANIMATION_PERIOD = 20; // ms

static const uint32_t BAR_PADDING   = 5;
static const uint32_t BAR_HEIGHT    = 15;
static const uint8_t BAR_COLOR      = 0xFF;

static const uint8_t LABEL_COLOR    = 0x44;
static const uint8_t DATA_COLOR     = 0xFF;

static const uint32_t GROUP_PADDING = 5;

static const uint32_t SIDE_PADDING  = 5;

static const char* IDLE_SCREEN_TEXT     = "KeepKey Wallet";
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


//====================== PRIVATE FUNCTION DECLARATIONS ========================


//-----------------------------------------------------------------------------
// 
static void
layout_animate(
        void* context 
);


//-----------------------------------------------------------------------------
// 
static void
layout_add_animation(
        AnimateCallback     callback,
        void*               data,
        uint32_t            duration
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
layout_clear_animations(
        void
);  



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
static void
layout_animate_tx_confirm(
        void*       data,
        uint32_t    duration,
        uint32_t    ellapsed
);


//-----------------------------------------------------------------------------
// 
static void
layout_clear(
        void
);


//=============================== FUNCTIONS ===================================


//-----------------------------------------------------------------------------
// See layout.h for public interface.
//
void
layout_init(
        Canvas* new_canvas
)
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
void
layout_home(
        void
)
{    
    layout_clear();

    DrawableParams sp;
    sp.y = ( canvas->height / 2 ) - ( font_height() / 2 );
    sp.x = 5;
    sp.color = 0x80;

    draw_string( canvas, IDLE_SCREEN_TEXT, &sp );
}


//-----------------------------------------------------------------------------
// See layout.h for public interface.
//
void
layout_sleep(
        void
)
{
    layout_clear();
}


//-----------------------------------------------------------------------------
// See layout.h for public interface.
//
void
layout_tx_info(
        const char* address,
        uint32_t    amount_in_satoshi
)
{
    layout_clear();

    DrawableParams sp;
    sp.x = 0;
    
    sp.y = GROUP_PADDING;
    sp.color = LABEL_COLOR;
    draw_string( canvas, ADDRESS_LABEL_TEXT, &sp );

    sp.y += font_height();
    sp.color = DATA_COLOR;
    draw_string( canvas, address, &sp );

    sp.y += font_height() + GROUP_PADDING;
    sp.color = LABEL_COLOR;
    draw_string( canvas, AMOUNT_LABEL_TEXT, &sp );

    sp.y += font_height();
    sp.color = DATA_COLOR;

    char buf[20]; // bbbbbbbb + . + ssssss + some feelgood pad.

    uint32_t major;
    uint32_t minor;
    if(amount_in_satoshi == 0)
    {
       major = minor = 0;
    } else {
        major = amount_in_satoshi / SATOSHI_PER_BTC;
        minor = amount_in_satoshi % SATOSHI_PER_BTC;
    }
    buf[0]='\0';
    //sprintf(buf, "%lu.%06lubtc", major, minor);

    draw_string( canvas, "buf", &sp );
}

//-----------------------------------------------------------------------------
// See layout.h for public interface.
//
void
layout_tx_confirmation(
        uint32_t confirmation_duration_ms
)
{
    layout_clear();

    DrawableParams sp;
    sp.x = SIDE_PADDING;
    sp.y = SIDE_PADDING;
    sp.color = LABEL_COLOR;
    draw_string( canvas, CONFIRM_LABEL_TEXT, &sp );

    static BoxDrawableParams box_params;
    box_params.base.y        = ( canvas->height / 2 ) - ( BAR_HEIGHT / 2 );
    box_params.base.x        = SIDE_PADDING;
    box_params.width         = 0;
    box_params.height        = BAR_HEIGHT;
    box_params.base.color    = BAR_COLOR;

    layout_add_animation( 
            &layout_animate_tx_confirm,
            (void*)&box_params,
            confirmation_duration_ms );
}

//-----------------------------------------------------------------------------
// See layout.h for public interface.
//
void
layout_firmware_update_confirmation(
        uint32_t confirmation_duration_ms
)
{
    layout_clear();

    DrawableParams sp;
    sp.x = SIDE_PADDING;
    sp.y = SIDE_PADDING;
    sp.color = LABEL_COLOR;
    draw_string( canvas, "Confirming firmware update...", &sp );

    static BoxDrawableParams box_params;
    box_params.base.y        = ( canvas->height / 2 ) - ( BAR_HEIGHT / 2 );
    box_params.base.x        = SIDE_PADDING;
    box_params.width         = 0;
    box_params.height        = BAR_HEIGHT;
    box_params.base.color    = BAR_COLOR;

    layout_add_animation( 
            &layout_animate_tx_confirm,
            (void*)&box_params,
            confirmation_duration_ms );
}


//-----------------------------------------------------------------------------
// See layout.h for public interface.
//
void
layout_standard_notification(
		const char* str1,
		const char* str2
)
{
    layout_clear();

    DrawableParams sp;
    sp.x = 0;

    sp.y = GROUP_PADDING;
    sp.color = DATA_COLOR;
    draw_string( canvas, str1, &sp );

    sp.y += font_height();
    sp.color = LABEL_COLOR;
    draw_string( canvas, str2, &sp );
}

//-----------------------------------------------------------------------------
// 
void
animate(
        void
)
{
    if( !animate_flag )
    {
        return;
    }

    Animation* animation = animation_queue_peek( &active_queue );

    while( animation != NULL )
    {
        Animation* next = animation->next;

        animation->ellapsed += ANIMATION_PERIOD;

        animation->animate_callback(
                animation->data,
                animation->duration,
                animation->ellapsed );

        if( ( animation->duration > 0 ) && ( animation->ellapsed >= animation->duration ) )
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
// See layout.h for public interface.
//
static void
layout_animate_tx_confirm(
        void*       data,
        uint32_t    duration,
        uint32_t    ellapsed
)
{
    BoxDrawableParams* box_params = (BoxDrawableParams*)data;

    uint32_t max_width = ( canvas->width - box_params->base.x - SIDE_PADDING );
    box_params->width = ( max_width * ( ellapsed ) ) / duration;

    draw_box( canvas, box_params );
}


//-----------------------------------------------------------------------------
// See layout.h for public interface.
//
static void
layout_clear(
        void
)
{
    layout_clear_animations();

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
static void
layout_animate(
        void* context 
)
{
    (void)context;

    animate_flag = true;
}


//-----------------------------------------------------------------------------
// 
static void
layout_add_animation(
        AnimateCallback callback,
        void*           data,
        uint32_t        duration
)
{
    Animation* animation = animation_queue_get( &active_queue, callback );

    if( animation == NULL )
    {
        animation = animation_queue_pop( &free_queue );
    }

    animation->data = data;
    animation->duration = duration;
    animation->ellapsed = 0;
    animation->animate_callback = callback;

    animation_queue_push( &active_queue, animation );
}


//-----------------------------------------------------------------------------
// 
#if defined(AGGRO_UNDEFINED_FN)
static void
layout_remove_animation(
        AnimateCallback  callback
)
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
static void
layout_clear_animations(
        void
)
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
static Animation*
animation_queue_peek(
        AnimationQueue* queue
)
{
    return queue->head;
}


//-----------------------------------------------------------------------------
// 
static void
animation_queue_push(
        AnimationQueue* queue,
        Animation*      node
)
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
static Animation*
animation_queue_pop(
        AnimationQueue* queue
)
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
static Animation*
animation_queue_get(
        AnimationQueue* queue,
        AnimateCallback callback
)
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

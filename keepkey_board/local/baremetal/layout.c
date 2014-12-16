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
#include "confirm_sm.h"


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
#define ANIMATION_PERIOD 20

/*
 * Margin
 */
#define TOP_MARGIN 	7
#define LEFT_MARGIN	4

/*
 * Title
 */
#define TITLE_COLOR 			0xFF
#define TITLE_WIDTH 			206
#define TITLE_ROWS 				1
#define TITLE_FONT_LINE_PADDING 0

/*
 * Body
 */
#define BODY_COLOR				0xFF
#define BODY_WIDTH				206
#define BODY_ROWS				3
#define BODY_FONT_LINE_PADDING	2

/*
 * Warning
 */
#define WARNING_COLOR 				0xFF
#define WARNING_WIDTH				256
#define WARNING_ROWS				1
#define WARNING_FONT_LINE_PADDING	0

/*
 * Default Layout
 */
#define NO_WIDTH 0;

#define AMOUNT_LABEL_TEXT	"Amount:"
#define ADDRESS_LABEL_TEXT	"Address:"
#define CONFIRM_LABEL_TEXT	"Confirming transaction..."


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

    static AnimationImageDrawableParams logo;
    logo.base.x = 104;
    logo.base.y = 12;
    logo.img_animation = get_logo_animation();

    layout_add_animation(
		&layout_animate_images,
		(void*)&logo,
		get_image_animation_duration(logo.img_animation));

    while(is_animating()){
		animate();
		display_refresh();
	}
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
     * Confirm text
     */
    sp.y = 46;
	sp.x = 215;
	sp.color = 0x66;

    /*
     * Determine animation/icon to show
     */
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
			sp.x = 209;
			draw_string(canvas, body_font, "confirmed", &sp, BODY_WIDTH, font_height(body_font) + 1);

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

void layout_warning(const char* prompt)
{
    layout_clear();

    const Font* font = get_title_font();

    /*
     * Format Title
     */
    char upper_prompt[warning_char_width()];
    strcpy(upper_prompt, "WARNING: ");
    strcat(upper_prompt, prompt);
    strupr(upper_prompt);

    /*
     * Title
     */
    DrawableParams sp;
    sp.x = (256 - calc_str_width(font, upper_prompt)) / 2;
    sp.y = 47;
    sp.color = TITLE_COLOR;
    draw_string(canvas, font, upper_prompt, &sp, WARNING_WIDTH, font_height(font));

    static AnimationImageDrawableParams warning;
    warning.img_animation = get_warning_animation();
    warning.base.y = 7;
    warning.base.x = 107;
    layout_add_animation(
		&layout_animate_images,
		(void*)&warning,
		0);
}

void layout_pin(const char* prompt, char pin[])
{
	DrawableParams sp;
	BoxDrawableParams box_params;

	/*
	 * Draw matrix
	 */
	for(uint8_t row = 0; row < 4; row++)
	{
		box_params.base.y = 7 + row * 17;
		box_params.base.x = 99;
		box_params.height = 1;
		box_params.width = 61;
		draw_box(canvas, &box_params);
	}
	for(uint8_t col = 0; col < 4; col++)
	{
		box_params.base.y = 7;
		box_params.base.x = 99 + col * 20;
		box_params.height = 52;
		box_params.width = 1;
		draw_box(canvas, &box_params);
	}

	/*
	 * Draw pin digits
	 */
	sp.color = 0xff;
	const Font* pin_font = get_pin_font();
	char pin_num[] = {0, 0};
	for(uint8_t row = 0; row < 3; row++)
		for(uint8_t col = 0; col < 3; col++)
		{
			uint8_t pad = 7;
			pin_num[0] = *pin++;

			/*
			 * Adjust pad
			 */
			if(pin_num[0] == '4' || pin_num[0] == '6' | pin_num[0] == '8' | pin_num[0] == '9')
				pad--;

			sp.y = 9 + row * 17;
			sp.x = 99 + pad + col * 20;
			draw_string(canvas, pin_font, pin_num, &sp, WARNING_WIDTH, font_height(pin_font));
		}

	/*
	 * Format prompt
	 */
	char upper_prompt[title_char_width()];
	strcpy(upper_prompt, prompt);
	strupr(upper_prompt);

    /*
     * Draw prompt
     */
	const Font* font = get_title_font();
    sp.y = 24;
    sp.x = 27;
    sp.color = 0x55;
    draw_string(canvas, font, upper_prompt, &sp, TITLE_WIDTH, font_height(font));
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

	while(is_animating()){
		animate();
		display_refresh();
	}
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
    	case FLASHING_ANIM:
			loading_animation.img_animation = get_flashing_animation();
			draw_bitmap_mono_rle(canvas, &sp, get_flashing_background_image());
			loading_animation.base.x = 29;
			loading_animation.base.y = 14;
			break;
    	case SENDING_ANIM:
			loading_animation.img_animation = get_sending_animation();
			draw_bitmap_mono_rle(canvas, &sp, get_sending_background_image());
			loading_animation.base.x = 22;
			loading_animation.base.y = 10;
			break;
    	case SIGNING_ANIM:
			loading_animation.img_animation = get_signing_animation();
			draw_bitmap_mono_rle(canvas, &sp, get_signing_background_image());
			loading_animation.base.x = 15;
			loading_animation.base.y = 20;
			break;
    }

    layout_add_animation(
		&layout_animate_images,
		(void*)&loading_animation,
		0);
}

//=========================== CONFIRM FUNCTIONS ================================

#define MAX_CYPHER_KEY_LEN 55
#define MAX_ENCRYPT_MSG_LEN 65

bool confirm_cipher(bool encrypt, const char *key)
{
	char key_prompt[MAX_CYPHER_KEY_LEN];

	strncpy(key_prompt, key, MAX_CYPHER_KEY_LEN -1);
	if(strlen(key) > (MAX_CYPHER_KEY_LEN - 4))
	{
		key_prompt[MAX_CYPHER_KEY_LEN - 4] = '.'; key_prompt[MAX_CYPHER_KEY_LEN - 3] = '.';
		key_prompt[MAX_CYPHER_KEY_LEN - 2] = '.'; key_prompt[MAX_CYPHER_KEY_LEN - 1] = '\0';
	}

	if(encrypt)
		return confirm("Encrypt Key Value", "Do you want to encrypt the value of the key \"%s\"?", key_prompt);
	else
		return confirm("Decrypt Key Value", "Do you want to decrypt the value of the key \"%s\"?", key_prompt);
}

bool confirm_encrypt_msg(const char *msg, bool signing)
{
	char msg_prompt[MAX_ENCRYPT_MSG_LEN];

	strncpy(msg_prompt, msg, MAX_ENCRYPT_MSG_LEN - 1);
	if(strlen(msg) > (MAX_ENCRYPT_MSG_LEN - 4))
	{
		msg_prompt[MAX_ENCRYPT_MSG_LEN - 4] = '.'; msg_prompt[MAX_ENCRYPT_MSG_LEN - 3] = '.';
		msg_prompt[MAX_ENCRYPT_MSG_LEN - 2] = '.'; msg_prompt[MAX_ENCRYPT_MSG_LEN - 1] = '\0';
	}

	if(signing)
		return confirm("Encrypt and Sign Message", "Do you want to encrypt and sign the message \"%s\"?", msg_prompt);
	else
		return confirm("Encrypt Message", "Do you want to encrypt the message \"%s\"?", msg_prompt);
}

bool confirm_decrypt_msg(const char *msg, const char *address)
{
	char msg_prompt[MAX_ENCRYPT_MSG_LEN];

	strncpy(msg_prompt, msg, MAX_ENCRYPT_MSG_LEN - 1);
	if(strlen(msg) > (MAX_ENCRYPT_MSG_LEN - 4))
	{
		msg_prompt[MAX_ENCRYPT_MSG_LEN - 4] = '.'; msg_prompt[MAX_ENCRYPT_MSG_LEN - 3] = '.';
		msg_prompt[MAX_ENCRYPT_MSG_LEN - 2] = '.'; msg_prompt[MAX_ENCRYPT_MSG_LEN - 1] = '\0';
	}

	if(address)
		return confirm("Decrypt Signed Message", "The decrypted, signed message is \"%s\"?", msg_prompt);
	else
		return confirm("Decrypt Message", "The decrypted message is \"%s\"?", msg_prompt);
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

uint32_t warning_char_width()
{
	const Font* font = get_title_font();
    return (WARNING_WIDTH / font_width(font)) * WARNING_ROWS;
}

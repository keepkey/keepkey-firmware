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

/* === Includes ============================================================ */

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "draw.h"
#include "font.h"
#include "keepkey_board.h"
#include "keepkey_display.h"
#include "layout.h"
#include "timer.h"
#include "resources.h"

/* === Private Variables =================================================== */

static AnimationQueue active_queue = { NULL, 0 };
static AnimationQueue free_queue = { NULL, 0 };
static Animation animations[ MAX_ANIMATIONS ];
static Canvas *canvas = NULL;
static volatile bool animate_flag = false;
static leaving_handler_t leaving_handler;

/* === Private Functions =================================================== */

/*
 *  layout_home_helper() - Splash home screen helper
 *
 *  INPUT
 *      - reversed: true/false whether splash animation is played in reverse
 *  OUTPUT
 *      none
 */
static void layout_home_helper(bool reversed)
{
    layout_clear();

    static AnimationImageDrawableParams logo;

#ifdef SALT_WHITELABEL
    logo.base.x = 60;
#else
    logo.base.x = 100;
#endif
    logo.base.y = 10;

    if(reversed)
    {
        logo.img_animation = get_logo_reversed_animation();
    }
    else
    {
        logo.img_animation = get_logo_animation();
    }

    layout_add_animation(
        &layout_animate_images,
        (void *)&logo,
        get_image_animation_duration(logo.img_animation));

    while(is_animating())
    {
        animate();
        display_refresh();
    }
}

/*
 * layout_animate_callback() - Callback function to set animation flag
 *
 * INPUT
 *     - context: animation context
 * OUTPUT
 *     none
 */
static void layout_animate_callback(void *context)
{
    (void)context;
    animate_flag = true;
}

/*
 * layout_remove_animation() - Remove animation node that contains the callback function from the queue
 *
 * INPUT
 *     - callback: animation callback function to remove node for
 * OUTPUT
 *     none
 */
#if defined(AGGRO_UNDEFINED_FN)
static void layout_remove_animation(AnimateCallback callback)
{
    Animation *animation = animation_queue_get(&active_queue, callback);

    if(animation != NULL)
    {
        animation_queue_push(&free_queue, animation);
    }
}
#endif

/*
 * animation_queue_peek() - Get current animation node in head pointer
 *
 * INPUT
 *     - queue: pointer to animation queue
 * OUTPUT
 *     node pointed to by head pointer
 */
static Animation *animation_queue_peek(AnimationQueue *queue)
{
    return queue->head;
}

/*
 * animation_queue_push() - Push animation into queue
 *
 * INPUT
 *     - queue: pointer to animation queue
 * OUTPUT
 *     none
 */
static void animation_queue_push(AnimationQueue *queue, Animation *node)
{
    if(queue->head != NULL)
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


/*
 * animation_queue_pop() - Pop a node from animation queue
 *
 * INPUT
 *     - queue: pointer to animation queue
 * OUTPUT
 *     pointer to a node from the queue
 */
static Animation *animation_queue_pop(AnimationQueue *queue)
{
    Animation *animation = queue->head;

    if(animation != NULL)
    {
        queue->head = animation->next;
        queue->size -= 1;
    }

    return(animation);
}

/*
 * animation_queue_get() - Get a queue containg the callback function
 *
 * INPUT
 *     - queue: pointer to animation queue
 *     - callback: animation callback function
 * OUTPUT
 *     pointer to Animation node
 */
static Animation *animation_queue_get(AnimationQueue *queue, AnimateCallback callback)
{
    Animation *current = queue->head;
    Animation *result = NULL;

    if(current != NULL)
    {
        if(current->animate_callback == callback)
        {
            result = current;
            queue->head = current->next;
        }
        else
        {
            Animation *previous = current;
            current = current->next;

            while((current != NULL) && (result == NULL))
            {
                // Found the node!
                if(current->animate_callback == callback)
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

    if(result != NULL)
    {
        queue->size -= 1;
    }

    return(result);
}

/* === Functions =========================================================== */

/*
 * layout_init() - Initialize layout subsystem
 *
 * INPUT
 *     - new_canvas: lay out info for specific image
 * OUTPUT
 *     none
 */
void layout_init(Canvas *new_canvas)
{
    canvas = new_canvas;

    int i;

    for(i = 0; i < MAX_ANIMATIONS; i++)
    {
        animation_queue_push(&free_queue, &animations[ i ]);
    }

    // Start the animation timer.
    post_periodic(&layout_animate_callback, NULL, ANIMATION_PERIOD, ANIMATION_PERIOD);
}

/*
 * layout_get_canvas() - Returns canvas for drawing to display
 *
 * INPUT
 *     none
 * OUTPUT
 *     pointer to canvas
 */
Canvas *layout_get_canvas(void)
{
    return canvas;
}

/*
 * call_leaving_handler() - Call leaving handler
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void call_leaving_handler(void)
{
    if(leaving_handler)
    {
        (*leaving_handler)();
    }
}

/*
 * layout_standard_notification() - Display standard notification
 *
 * INPUT
 *     - str1: title string
 *     - str2: body string
 *     - type: notification type
 * OUTPUT
 *     none
 */
void layout_standard_notification(const char *str1, const char *str2,
                                  NotificationType type)
{
    call_leaving_handler();
    layout_clear();

    DrawableParams sp;
    const Font *title_font = get_title_font();
    const Font *body_font = get_body_font();
    const uint32_t body_line_count = calc_str_line(body_font, str2, BODY_WIDTH);

    /* Determine vertical alignment and body width */
    sp.y = TOP_MARGIN;

    if(body_line_count == ONE_LINE)
    {
        sp.y = TOP_MARGIN_FOR_ONE_LINE;
    }
    else if(body_line_count == TWO_LINES)
    {
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
    draw_string(canvas, body_font, str2, &sp, BODY_WIDTH,
                font_height(body_font) + BODY_FONT_LINE_PADDING);

    layout_notification_icon(type, &sp);
}

/*
 * layout_notification_icon() - Display notification icon
 *
 * INPUT
 *     - type: notification type
 *     - sp: drawable parameters for icon notification placement
 * OUTPUT
 *     none
 */
void layout_notification_icon(NotificationType type, DrawableParams *sp)
{
    /* Determine animation/icon to show */
    static AnimationImageDrawableParams icon;

    switch(type)
    {
        case NOTIFICATION_REQUEST:
            icon.base.x = 233;
            icon.base.y = 4;
            icon.img_animation = get_confirm_icon_animation();

            layout_add_animation(
                &layout_animate_images,
                (void *)&icon,
                get_image_animation_duration(icon.img_animation));
            break;

        case NOTIFICATION_REQUEST_NO_ANIMATION:
            sp->x = 233;
            sp->y = 4;
            draw_bitmap_mono_rle(canvas, sp, get_confirm_icon_image());
            break;

        case NOTIFICATION_CONFIRM_ANIMATION:
            icon.base.x = 231;
            icon.base.y = 2;
            icon.img_animation = get_confirming_animation();

            layout_add_animation(
                &layout_animate_images,
                (void *)&icon,
                get_image_animation_duration(icon.img_animation));
            break;

        case NOTIFICATION_CONFIRMED:
            sp->x = 231;
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
 * layout_warning() - Display warning message
 *
 * INPUT
 *     - prompt: string to display
 * OUTPUT
 *     none
 */
void layout_warning(const char *str)
{
    call_leaving_handler();
    layout_clear();

    const Font *font = get_body_font();

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
    layout_add_animation(&layout_animate_images, (void *)&warning, 0);
}

/*
 * layout_warning_static() - Display warning message on display without animation
 *
 * INPUT
 *     - prompt: string to display
 * OUTPUT
 *     none
 */
void layout_warning_static(const char *str)
{
    call_leaving_handler();
    layout_clear();

    const Font *font = get_body_font();

    /* Title */
    DrawableParams sp;
    sp.x = (KEEPKEY_DISPLAY_WIDTH - calc_str_width(font, str)) / 2;
    sp.y = 50;
    sp.color = TITLE_COLOR;
    draw_string(canvas, font, str, &sp, KEEPKEY_DISPLAY_WIDTH, font_height(font));

    sp.x = 107;
    sp.y = 7;
    draw_bitmap_mono_rle(canvas, &sp, get_warning_image());

    display_refresh();
}

/*
 * layout_simple_message() - Displays a simple one line message
 *
 * INPUT
 *     - str: string to display
 * OUTPUT
 *     none
 */
void layout_simple_message(const char *str)
{
    call_leaving_handler();
    layout_clear();

    const Font *font = get_title_font();

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

    display_refresh();
}

/*
 * layout_version() - Displays version
 *
 * INPUT
 *     - major: major version number
 *     - minor: minor version number
 *     - patch: patch version number
 * OUTPUT
 *     none
 */
void layout_version(int32_t major, int32_t minor, int32_t patch)
{
    char version_info[SMALL_STR_BUF];

    call_leaving_handler();

    const Font *font = get_body_font();

    snprintf(version_info, SMALL_STR_BUF, "v%lu.%lu.%lu", (unsigned long)major,
             (unsigned long)minor, (unsigned long)patch);

    /* Draw version information */
    DrawableParams sp;
    sp.x = KEEPKEY_DISPLAY_WIDTH - calc_str_width(font, version_info) - BODY_FONT_LINE_PADDING;
    sp.y = KEEPKEY_DISPLAY_HEIGHT - font_height(font) - BODY_FONT_LINE_PADDING;
    sp.color = 0x22;
    draw_string(canvas, font, version_info, &sp, KEEPKEY_DISPLAY_WIDTH, font_height(font));

    display_refresh();
}

/*
 *  layout_home() - Splash home screen
 *
 *  INPUT
 *      none
 *  OUTPUT
 *      none
 */
void layout_home(void)
{
    layout_home_helper(false);
}

/*
 *  layout_home_reversed() - Splash home screen in reverse
 *
 *  INPUT
 *      none
 *  OUTPUT
 *      none
 */
void layout_home_reversed(void)
{
    layout_home_helper(true);
}

/*
 * layout_loading() - Loading animation
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
void layout_loading(void)
{
    static AnimationImageDrawableParams loading_animation;

    call_leaving_handler();
    layout_clear();

    loading_animation.img_animation = get_loading_animation();
    loading_animation.base.x = 83;
    loading_animation.base.y = 29;
    layout_add_animation(&layout_animate_images, (void *)&loading_animation, 0);
    force_animation_start();
}

/*
 * animate() - Attempt to animate if there are animations in the queue
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void animate(void)
{
    if(animate_flag)
    {
        Animation *animation = animation_queue_peek(&active_queue);

        while(animation != NULL)
        {
            Animation *next = animation->next;

            animation->elapsed += ANIMATION_PERIOD;

            animation->animate_callback(
                animation->data,
                animation->duration,
                animation->elapsed);

            if((animation->duration > 0) && (animation->elapsed >= animation->duration))
            {
                animation_queue_push(
                    &free_queue,
                    animation_queue_get(&active_queue, animation->animate_callback));
            }

            animation = next;
        }

        animate_flag = false;
    }
}

/*
 * is_animating() - Get animation status
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false whether there are animations in the queue
 */
bool is_animating(void)
{
    if(animation_queue_peek(&active_queue) == NULL)
    {
        return false;
    }
    else
    {
        return true;
    }
}

/*
 * layout_animate_images() - Animate image on display
 *
 * INPUT
 *     - data: pointer to image
 *     - duration: duration of the image animation
 *     - elapsed: delay before drawing the image
 * OUTPUT
 *     none
 */
void layout_animate_images(void *data, uint32_t duration, uint32_t elapsed)
{
    const Image *img;
    AnimationImageDrawableParams *animation_img_params = (AnimationImageDrawableParams *)data;

    if(duration == 0)  // looping
    {
        img = get_image_animation_frame(animation_img_params->img_animation, elapsed, true);
    }
    else
    {
        img = get_image_animation_frame(animation_img_params->img_animation, elapsed, false);
    }

    if(img != NULL)
    {
        draw_bitmap_mono_rle(canvas, &animation_img_params->base, img);
    }
}

/*
 * layout_clear() - Clear animation queue and clear display
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void layout_clear(void)
{
    layout_clear_animations();

    layout_clear_static();

}

/*
 * layout_clear_static() - Clear display
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void layout_clear_static(void)
{
    BoxDrawableParams bp;
    bp.width = canvas->width;
    bp.height = canvas->height;
    bp.base.x = 0;
    bp.base.y = 0;
    bp.base.color = 0x00;

    draw_box(canvas, &bp);
}

/*
 * force_animation_start() - Direct call to start animation
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void force_animation_start(void)
{
    animate_flag = true;
}

/*
 * animating_progress_handler() - Animate storage update progress
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void animating_progress_handler(void)
{
    if(is_animating())
    {
        animate();
        display_refresh();
    }
}

/*
 * layout_add_animation() - Queue up the animation in active_queue
 *
 * INPUT
 *     - callback: animation callback function
 *     - data: pointer to image
 *     - duration: duration of animation
 * OUTPUT
 *     none
 */
void layout_add_animation(AnimateCallback callback, void *data, uint32_t duration)
{
    Animation *animation = animation_queue_get(&active_queue, callback);

    if(animation == NULL)
    {
        animation = animation_queue_pop(&free_queue);
    }

    animation->data = data;
    animation->duration = duration;
    animation->elapsed = 0;
    animation->animate_callback = callback;
    animation_queue_push(&active_queue, animation);
}

/*
 * layout_clear_animations() - Clear all animation from queue
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void layout_clear_animations(void)
{
    Animation *animation = animation_queue_pop(&active_queue);

    while(animation != NULL)
    {
        animation_queue_push(&free_queue, animation);
        animation = animation_queue_pop(&active_queue);
    }
}

/*
 * set_leaving_handler() - Setup leaving handler
 *
 * INPUT
 *     - leaving_func: leaving handler to be set
 * OUTPUT
 *     none
 */
void set_leaving_handler(leaving_handler_t leaving_func)
{
    leaving_handler = leaving_func;
}

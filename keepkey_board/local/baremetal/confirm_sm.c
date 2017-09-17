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

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libopencm3/cm3/cortex.h>

#include "keepkey_display.h"
#include "keepkey_button.h"
#include "timer.h"
#include "layout.h"
#include "msg_dispatch.h"
#include "confirm_sm.h"
#include "usb_driver.h"

/* === Private Variables =================================================== */

/* Button request ack */
static bool button_request_acked = false;

/* === Variables =========================================================== */

extern bool reset_msg_stack;

/* === Private Functions =================================================== */

/*
 * handle_screen_press() - Handler for push button being pressed
 *
 * INPUT
 *     - context: current state context
 * OUTPUT
 *     none
 */
static void handle_screen_press(void *context)
{
    assert(context != NULL);

    StateInfo *si = (StateInfo *)context;

    if(button_request_acked)
    {
        switch(si->display_state)
        {
            case HOME:
                si->active_layout = LAYOUT_CONFIRM_ANIMATION;
                si->display_state = CONFIRM_WAIT;
                break;

            default:
                break;
        }
    }
}

/*
 * handle_screen_release() - Handler for push button being released
 *
 * INPUT
 *     - context: current state context
 * OUTPUT
 *     none
 */
static void handle_screen_release(void *context)
{
    assert(context != NULL);

    StateInfo *si = (StateInfo *)context;

    switch(si->display_state)
    {
        case CONFIRM_WAIT:
            si->active_layout = LAYOUT_REQUEST_NO_ANIMATION;
            si->display_state = HOME;
            break;

        case CONFIRMED:
            si->active_layout = LAYOUT_FINISHED;
            si->display_state = FINISHED;
            break;

        default:
            break;
    }
}

/*
 * handle_confirm_timeout() - User has held down the push button for duration as request.
 *
 * INPUT
 *     - context: current state context
 * OUTPUT
 *     none
 */

static void handle_confirm_timeout(void *context)
{
    assert(context != NULL);

    StateInfo *si = (StateInfo *)context;
    si->display_state = CONFIRMED;
    si->active_layout = LAYOUT_CONFIRMED;
}

/*
 * swap_layout() - Changes the active layout of the confirmation screen
 *
 * INPUT
 *     - active_layout: layout to switch to
 *     - si: current state information
 *     - layout_notification_func: layout notification function to use to display confirm message
 * OUTPUT
 *     none
 */
static void swap_layout(ActiveLayout active_layout, volatile StateInfo *si,
                        layout_notification_t layout_notification_func)
{
    switch(active_layout)
    {
        case LAYOUT_REQUEST:
            (*layout_notification_func)(si->lines[active_layout].request_title,
                                        si->lines[active_layout].request_body, NOTIFICATION_REQUEST);
            remove_runnable(&handle_confirm_timeout);
            break;

        case LAYOUT_REQUEST_NO_ANIMATION:
            (*layout_notification_func)(si->lines[active_layout].request_title,
                                        si->lines[active_layout].request_body, NOTIFICATION_REQUEST_NO_ANIMATION);
            remove_runnable(&handle_confirm_timeout);
            break;

        case LAYOUT_CONFIRM_ANIMATION:
            (*layout_notification_func)(si->lines[active_layout].request_title,
                                        si->lines[active_layout].request_body, NOTIFICATION_CONFIRM_ANIMATION);
            post_delayed(&handle_confirm_timeout, (void *)si, CONFIRM_TIMEOUT_MS);
            break;

        case LAYOUT_CONFIRMED:

            /* Finish confirming animation */
            while(is_animating())
            {
                animate();
                display_refresh();
            }

            (*layout_notification_func)(si->lines[active_layout].request_title,
                                        si->lines[active_layout].request_body, NOTIFICATION_CONFIRMED);
            remove_runnable(&handle_confirm_timeout);
            break;

        default:
            assert(0);
    };

}

/*
 * confirm_helper() - Common confirm function
 *
 * INPUT
 *     - request_title: title of confirmation request
 *     - request_body: body of confirmation message
 *     - layout_notification_func: layout notification function to use to display confirm message
 * OUTPUT
 *     true/false whether device confirmed
 */
static bool confirm_helper(const char *request_title, const char *request_body,
                      layout_notification_t layout_notification_func)
{
    bool ret_stat = false;
    volatile StateInfo state_info;
    ActiveLayout new_layout, cur_layout;
    DisplayState new_ds;
    uint16_t tiny_msg;
    uint8_t msg_tiny_buf[MSG_TINY_BFR_SZ];

#if DEBUG_LINK
    DebugLinkDecision *dld;
    bool debug_decided = false;
#endif

    reset_msg_stack = false;

    memset((void *)&state_info, 0, sizeof(state_info));
    state_info.display_state = HOME;
    state_info.active_layout = LAYOUT_REQUEST;

    /* Request */
    state_info.lines[LAYOUT_REQUEST].request_title = request_title;
    state_info.lines[LAYOUT_REQUEST].request_body = request_body;
    state_info.lines[LAYOUT_REQUEST_NO_ANIMATION].request_title = request_title;
    state_info.lines[LAYOUT_REQUEST_NO_ANIMATION].request_body = request_body;

    /* Confirming */
    state_info.lines[LAYOUT_CONFIRM_ANIMATION].request_title = request_title;
    state_info.lines[LAYOUT_CONFIRM_ANIMATION].request_body = request_body;

    /* Confirmed */
    state_info.lines[LAYOUT_CONFIRMED].request_title = request_title;
    state_info.lines[LAYOUT_CONFIRMED].request_body = request_body;

    keepkey_button_set_on_press_handler(&handle_screen_press, (void *)&state_info);
    keepkey_button_set_on_release_handler(&handle_screen_release, (void *)&state_info);

    cur_layout = LAYOUT_INVALID;

    while(1)
    {
        cm_disable_interrupts();
        new_layout = state_info.active_layout;
        new_ds = state_info.display_state;
        cm_enable_interrupts();

        /* Don't process usb tiny message unless usb has been initialized */
        if(get_usb_init_stat())
        {
            /* Listen for tiny messages */
            tiny_msg = check_for_tiny_msg(msg_tiny_buf);

            switch(tiny_msg)
            {
                case MessageType_MessageType_ButtonAck:
                    button_request_acked = true;
                    break;

                case MessageType_MessageType_Cancel:
                case MessageType_MessageType_Initialize:
                    if(tiny_msg == MessageType_MessageType_Initialize)
                    {
                        reset_msg_stack = true;
                    }

                    ret_stat  = false;
                    goto confirm_helper_exit;
#if DEBUG_LINK

                case MessageType_MessageType_DebugLinkDecision:
                    dld = (DebugLinkDecision *)msg_tiny_buf;
                    ret_stat = dld->yes_no;
                    debug_decided = true;
                    break;

                case MessageType_MessageType_DebugLinkGetState:
                    call_msg_debug_link_get_state_handler((DebugLinkGetState *)msg_tiny_buf);
                    break;
#endif

                default:
                    break; /* break from switch statement and stay in the while loop*/
            }
        }

        if(new_ds == FINISHED)
        {
            ret_stat = true;
            break; /* confirmation done.  Exiting function */
        }

        if(cur_layout != new_layout)
        {
            swap_layout(new_layout, &state_info, layout_notification_func);
            cur_layout = new_layout;
        }

#if DEBUG_LINK

        if(debug_decided && button_request_acked)
        {
            break; /* confirmation done via debug link.  Exiting function */
        }

#endif

        display_refresh();
        animate();
    }

confirm_helper_exit:

    keepkey_button_set_on_press_handler(NULL, NULL);
    keepkey_button_set_on_release_handler(NULL, NULL);

    return(ret_stat);
}

/* === Functions =========================================================== */

/*
 *  confirm() - User confirmation function interface
 *
 *  INPUT
 *      - type: type of button request to send to host
 *      - request_title: title of confirm message
 *      - request_body: body of confirm message
 *  OUTPUT
 *      true/false whether device confirmed
 */
bool confirm(ButtonRequestType type, const char *request_title, const char *request_body,
             ...)
{
    button_request_acked = false;

    va_list vl;
    va_start(vl, request_body);
    char strbuf[BODY_CHAR_MAX];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    vsnprintf(strbuf, BODY_CHAR_MAX, request_body, vl);
#pragma clang diagnostic pop
    va_end(vl);

    /* Send button request */
    ButtonRequest resp;
    memset(&resp, 0, sizeof(ButtonRequest));
    resp.has_code = true;
    resp.code = type;
    msg_write(MessageType_MessageType_ButtonRequest, &resp);

    return confirm_helper(request_title, strbuf, &layout_standard_notification);
}

/*
 *  confirm_with_custom_button_request() - User confirmation function interface
 *
 *  INPUT
 *      - button_request: custom button request to send to host
 *      - request_title: title of confirm message
 *      - request_body: body of confirm message
 *  OUTPUT
 *      true/false whether device confirmed
 */
bool confirm_with_custom_button_request(ButtonRequest *button_request,
                                        const char *request_title, const char *request_body,
                                        ...)
{
    button_request_acked = false;

    va_list vl;
    va_start(vl, request_body);
    char strbuf[BODY_CHAR_MAX];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    vsnprintf(strbuf, BODY_CHAR_MAX, request_body, vl);
#pragma clang diagnostic pop
    va_end(vl);

    /* Send button request */
    msg_write(MessageType_MessageType_ButtonRequest, button_request);

    return confirm_helper(request_title, strbuf, &layout_standard_notification);
}

/*
 *  confirm_with_custom_layout() - User confirmation function interface that allows custom layout notification
 *
 *  INPUT
 *      - layout_notification_func: custom layout notification
 *      - type: type of button request to send to host
 *      - request_title: title of confirm message
 *      - request_body: body of confirm message
 *  OUTPUT
 *      true/false whether device confirmed
 */
bool confirm_with_custom_layout(layout_notification_t layout_notification_func,
                                ButtonRequestType type,
                                const char *request_title, const char *request_body, ...)
{
    button_request_acked = false;

    va_list vl;
    va_start(vl, request_body);
    char strbuf[BODY_CHAR_MAX];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    vsnprintf(strbuf, BODY_CHAR_MAX, request_body, vl);
#pragma clang diagnostic pop
    va_end(vl);

    /* Send button request */
    ButtonRequest resp;
    memset(&resp, 0, sizeof(ButtonRequest));
    resp.has_code = true;
    resp.code = type;
    msg_write(MessageType_MessageType_ButtonRequest, &resp);

    return confirm_helper(request_title, strbuf, layout_notification_func);
}

/*
 * confirm_without_button_request() - User confirmation function interface without button request
 *
 * INPUT
 *     - request_title: title of confirmation request
 *     - request_body: body of confirmation message
 * OUTPUT
 *     true/false whether device confirmed
 */
bool confirm_without_button_request(const char *request_title, const char *request_body,
                                    ...)
{
    button_request_acked = true;

    va_list vl;
    va_start(vl, request_body);
    char strbuf[BODY_CHAR_MAX];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    vsnprintf(strbuf, BODY_CHAR_MAX, request_body, vl);
#pragma clang diagnostic pop
    va_end(vl);

    return confirm_helper(request_title, strbuf, &layout_standard_notification);
}

/*
 * review() - Acts like confirm but always returns true even if it was canceled via host
 *
 * INPUT
 *     - type: type of button request to send to host
 *     - request_title: title of confirmation request
 *     - request_body: body of confirmation message
 * OUTPUT
 *     true/false whether device confirmed
 *
 */
bool review(ButtonRequestType type, const char *request_title, const char *request_body,
            ...)
{
    button_request_acked = false;

    va_list vl;
    va_start(vl, request_body);
    char strbuf[BODY_CHAR_MAX];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    vsnprintf(strbuf, BODY_CHAR_MAX, request_body, vl);
#pragma clang diagnostic pop
    va_end(vl);

    /* Send button request */
    ButtonRequest resp;
    memset(&resp, 0, sizeof(ButtonRequest));
    resp.has_code = true;
    resp.code = type;
    msg_write(MessageType_MessageType_ButtonRequest, &resp);

    confirm_helper(request_title, strbuf, &layout_standard_notification);
    return true;
}

/*
 * review_without_button_request() - User review function interface without button request
 *
 * INPUT
 *     - request_title: title of confirmation request
 *     - request_body: body of confirmation message
 * OUTPUT
 *     true/false whether device confirmed
 *
 */
bool review_without_button_request(const char *request_title, const char *request_body,
                                   ...)
{
    button_request_acked = true;

    va_list vl;
    va_start(vl, request_body);
    char strbuf[BODY_CHAR_MAX];
    vsnprintf(strbuf, BODY_CHAR_MAX, request_body, vl);
    va_end(vl);

    confirm_helper(request_title, strbuf, &layout_standard_notification);
    return true;
}
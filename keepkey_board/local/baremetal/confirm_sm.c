/* START KEEPKEY LICENSE */
/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2014 Carbon Design Group <tom@carbondesign.com>
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

/*
 * @brief General confirmation state machine.
 */

//================================ INCLUDES =================================== 
#include <assert.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libopencm3/cm3/cortex.h>

#include <keepkey_display.h>
#include <keepkey_button.h>
#include <timer.h>
#include <layout.h>

#include <confirm_sm.h>

//====================== CONSTANTS, TYPES, AND MACROS =========================
typedef enum
{
    HOME,
    CONFIRM_WAIT,
    CONFIRMED,
    FINISHED
} DisplayState;

typedef enum
{
    LAYOUT_REQUEST,
    LAYOUT_CONFIRM_ANIMATION,
    LAYOUT_CONFIRMED,
    LAYOUT_FINISHED,
    LAYOUT_NUM_LAYOUTS,
    LAYOUT_INVALID
} ActiveLayout;

/**
 * Define the given layout dialog texts for each screen
 */
typedef struct
{
    const char* request_title;
    const char* request_body;
} ScreenLine;
typedef ScreenLine ScreenLines;
typedef ScreenLines DialogLines[LAYOUT_NUM_LAYOUTS];

typedef struct 
{
    DialogLines lines;
    DisplayState display_state;
    ActiveLayout active_layout;
} StateInfo;

/*
 * The number of milliseconds to wait for a confirmation
 */
#define CONFIRM_TIMEOUT_MS (1800)

//=============================== VARIABLES ===================================

//====================== PRIVATE FUNCTION DECLARATIONS ========================
static void handle_screen_press(void* context);
static void handle_screen_release(void* context);
static void handle_confirm_timeout(void* context);

//=============================== FUNCTIONS ===================================

/**
 * Handles user key-down event.
 */
static void handle_screen_press(void* context)
{
    assert(context != NULL);

    StateInfo *si = (StateInfo*)context;

    switch( si->display_state )
    {
        case HOME:
            si->active_layout = LAYOUT_CONFIRM_ANIMATION;
            si->display_state = CONFIRM_WAIT;
            break;

        default:
            break;
    }
}

/**
 * Handles the scenario in which a button is released.  During the confirmation period, this
 * indicates the user stopped their confirmation/aborted.
 *
 * @param context unused
 */
static void handle_screen_release( void* context)
{
    assert(context != NULL);

    StateInfo *si = (StateInfo*)context;

    switch( si->display_state )
    {
        case CONFIRM_WAIT:
            si->active_layout = LAYOUT_REQUEST;
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

/**
 * This is the success path for confirmation, and indicates that the confirmation timer
 * has expired.
 *
 * @param context The state info used to apss info back to the user.
 */

static void handle_confirm_timeout( void* context )
{
    assert(context != NULL);

    StateInfo *si = (StateInfo*)context;
    si->display_state = CONFIRMED;
    si->active_layout = LAYOUT_CONFIRMED;
}

void swap_layout(ActiveLayout active_layout, volatile StateInfo* si)
{
    switch(active_layout)
    {
    	case LAYOUT_REQUEST:
    		layout_standard_notification(si->lines[active_layout].request_title, si->lines[active_layout].request_body, NOTIFICATION_REQUEST);
            remove_runnable( &handle_confirm_timeout );
    		break;
    	case LAYOUT_CONFIRM_ANIMATION:
    		layout_standard_notification(si->lines[active_layout].request_title, si->lines[active_layout].request_body, NOTIFICATION_CONFIRM_ANIMATION);
    		post_delayed( &handle_confirm_timeout, (void*)si, CONFIRM_TIMEOUT_MS );
    		break;
    	case LAYOUT_CONFIRMED:
    		layout_standard_notification(si->lines[active_layout].request_title, si->lines[active_layout].request_body, NOTIFICATION_CONFIRMED);
    		remove_runnable( &handle_confirm_timeout );
    		break;
    	default:
    		assert(0);
    };

}

bool confirm(const char *request_title, const char *request_body, ...)
{
    bool ret=false;

    va_list vl;
    va_start(vl, request_body);
    char strbuf[body_char_width()+1];
    vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
    va_end(vl);

    volatile StateInfo state_info;
    memset((void*)&state_info, 0, sizeof(state_info));
    state_info.display_state = HOME;
    state_info.active_layout = LAYOUT_REQUEST;

    /*
     * Request
     */
    state_info.lines[LAYOUT_REQUEST].request_title = request_title;
    state_info.lines[LAYOUT_REQUEST].request_body = strbuf;

    /*
	 * Confirming
	 */
	state_info.lines[LAYOUT_CONFIRM_ANIMATION].request_title = request_title;
	state_info.lines[LAYOUT_CONFIRM_ANIMATION].request_body = strbuf;

    /*
     * Confirmed
     */
    state_info.lines[LAYOUT_CONFIRMED].request_title = request_title;
    state_info.lines[LAYOUT_CONFIRMED].request_body = strbuf;

    keepkey_button_set_on_press_handler( &handle_screen_press, (void*)&state_info );
    keepkey_button_set_on_release_handler( &handle_screen_release, (void*)&state_info );

    ActiveLayout cur_layout = LAYOUT_INVALID;
    while(1)
    {
        cm_disable_interrupts();
    	ActiveLayout new_layout = state_info.active_layout;
    	DisplayState new_ds = state_info.display_state;
        cm_enable_interrupts();

        if(new_ds == FINISHED)
        {
            ret = true;
            break;
        }

        if(cur_layout != new_layout)
        {
            swap_layout(new_layout, &state_info);
            cur_layout = new_layout;
        }

        display_refresh();
        animate();
    }

    keepkey_button_set_on_press_handler( NULL, NULL );
    keepkey_button_set_on_release_handler( NULL, NULL );

    return ret;
}



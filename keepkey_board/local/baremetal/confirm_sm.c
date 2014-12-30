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
#include <messages.h>
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

/*
 * Button request ack
 */
static bool button_request_acked = false;

/*
 * Flag whether confirm was canceled by init msg
 */
static bool confirm_canceled_by_init = false;

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

    if(button_request_acked)
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

bool confirm_with_button_request(ButtonRequestType type, const char *request_title, const char *request_body, ...)
{
	button_request_acked = false;

	va_list vl;
	va_start(vl, request_body);
	char strbuf[body_char_width()+1];
	vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
	va_end(vl);

	/*
	 * Send button request
	 */
	ButtonRequest resp;
	memset(&resp, 0, sizeof(ButtonRequest));
	resp.has_code = true;
	resp.code = type;
	msg_write(MessageType_MessageType_ButtonRequest, &resp);

	return confirm_helper(request_title, strbuf);
}

bool confirm(const char *request_title, const char *request_body, ...)
{
	button_request_acked = true;

	va_list vl;
	va_start(vl, request_body);
	char strbuf[body_char_width()+1];
	vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
	va_end(vl);

	return confirm_helper(request_title, strbuf);
}

bool review(const char *request_title, const char *request_body, ...)
{
	button_request_acked = true;

	va_list vl;
	va_start(vl, request_body);
	char strbuf[body_char_width()+1];
	vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
	va_end(vl);

	confirm_helper(request_title, strbuf);
	return true;
}

bool confirm_helper(const char *request_title, const char *request_body)
{
    bool ret=false;
    confirm_canceled_by_init = false;

    volatile StateInfo state_info;
    memset((void*)&state_info, 0, sizeof(state_info));
    state_info.display_state = HOME;
    state_info.active_layout = LAYOUT_REQUEST;

    /*
     * Request
     */
    state_info.lines[LAYOUT_REQUEST].request_title = request_title;
    state_info.lines[LAYOUT_REQUEST].request_body = request_body;

    /*
	 * Confirming
	 */
	state_info.lines[LAYOUT_CONFIRM_ANIMATION].request_title = request_title;
	state_info.lines[LAYOUT_CONFIRM_ANIMATION].request_body = request_body;

    /*
     * Confirmed
     */
    state_info.lines[LAYOUT_CONFIRMED].request_title = request_title;
    state_info.lines[LAYOUT_CONFIRMED].request_body = request_body;

    keepkey_button_set_on_press_handler( &handle_screen_press, (void*)&state_info );
    keepkey_button_set_on_release_handler( &handle_screen_release, (void*)&state_info );

    ActiveLayout cur_layout = LAYOUT_INVALID;
    while(1)
    {
        cm_disable_interrupts();
    	ActiveLayout new_layout = state_info.active_layout;
    	DisplayState new_ds = state_info.display_state;
        cm_enable_interrupts();

        /*
         * Listen for tiny messages
         */
        uint16_t tiny_msg = check_for_tiny_msg(false);

        /*
         * If ack received, let user confirm
         */
        if(tiny_msg == MessageType_MessageType_ButtonAck)
        	button_request_acked = true;

        /*
         * Check for cancel or initialize messages
         */
		if (tiny_msg == MessageType_MessageType_Cancel || tiny_msg == MessageType_MessageType_Initialize) {
			if (tiny_msg == MessageType_MessageType_Initialize) {
				confirm_canceled_by_init = true;
			}
			ret = false;
			break;
		}

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

void cancel_confirm(FailureType code, const char *text)
{
	if(confirm_canceled_by_init)
		call_msg_initialize_handler();
	else
		call_msg_failure_handler(code, text);

	confirm_canceled_by_init = false;
}

void success_confirm(const char *text)
{
	if(confirm_canceled_by_init)
		call_msg_initialize_handler();
	else
		call_msg_success_handler(text);

	confirm_canceled_by_init = false;
}

//=========================== CONFIRM FUNCTIONS ================================

#define MAX_CYPHER_KEY_LEN 55
#define MAX_ENCRYPT_MSG_LEN 65
#define MAX_PING_MSG_LEN 36

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
		return confirm_with_button_request(ButtonRequestType_ButtonRequest_Other,
			"Encrypt Key Value", "Do you want to encrypt the value of the key \"%s\"?", key_prompt);
	else
		return confirm_with_button_request(ButtonRequestType_ButtonRequest_Other,
			"Decrypt Key Value", "Do you want to decrypt the value of the key \"%s\"?", key_prompt);
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
		return confirm_with_button_request(ButtonRequestType_ButtonRequest_ProtectCall,
			"Encrypt and Sign Message", "Do you want to encrypt and sign the message \"%s\"?", msg_prompt);
	else
		return confirm_with_button_request(ButtonRequestType_ButtonRequest_ProtectCall,
			"Encrypt Message", "Do you want to encrypt the message \"%s\"?", msg_prompt);
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
		return confirm_with_button_request(ButtonRequestType_ButtonRequest_Other,
			"Decrypt Signed Message", "The decrypted, signed message is \"%s\"?", msg_prompt);
	else
		return confirm_with_button_request(ButtonRequestType_ButtonRequest_Other,
			"Decrypt Message", "The decrypted message is \"%s\"?", msg_prompt);
}

bool confirm_ping_msg(const char *msg)
{
	if(strlen(msg) <= MAX_PING_MSG_LEN)
		return confirm_with_button_request(ButtonRequestType_ButtonRequest_ProtectCall,
			"Respond to Ping Request", "A ping request was received with the message \"%s\". Would you like to have it responded to?", msg);
	else
		return confirm_with_button_request(ButtonRequestType_ButtonRequest_ProtectCall,
			"Respond to Ping Request", "A ping request was received. Would you like to have it responded to?");
}

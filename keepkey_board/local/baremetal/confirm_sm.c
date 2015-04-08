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
#include <msg_dispatch.h>
#include <confirm_sm.h>


/******************** Static/Global variables *************************/
/* Button request ack */
static bool button_request_acked = false;
extern bool reset_msg_stack;

/******************** Static Function Declarations ********************/
static void handle_screen_press(void* context);
static void handle_screen_release(void* context);
static void handle_confirm_timeout(void* context);

/*
 * handle_screen_press() - handler for push button being pressed
 *
 * INPUT - 
 *      *context
 * OUTPUT - none
 */
static void handle_screen_press(void* context)
{
    assert(context != NULL);

    StateInfo *si = (StateInfo*)context;

    if(button_request_acked) {
		switch( si->display_state ) {
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
 * handle_screen_release() - handler for push button being released 
 *
 * INPUT - 
 *      *context - unused 
 * OUTPUT 
 *      none 
 */
static void handle_screen_release( void* context)
{
    assert(context != NULL);

    StateInfo *si = (StateInfo*)context;

    switch( si->display_state ) {
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
 * handle_confirm_timeout() - user has held down the push button for duration as request.  
 *                      the confirmation is successful
 *
 * INPUT - 
 *      *context - not used
 * OUTPUT - 
 *      none
 */

static void handle_confirm_timeout( void* context )
{
    assert(context != NULL);

    StateInfo *si = (StateInfo*)context;
    si->display_state = CONFIRMED;
    si->active_layout = LAYOUT_CONFIRMED;
}

/*
 * swap_layout() - 
 *
 * INPUT -
 *      active_layout - 
 *      *si - 
 *      *layout_notification_func - layout notification function to use to display confirm message
 * OUTPUT - 
 *      none
 */
void swap_layout(ActiveLayout active_layout, volatile StateInfo* si, layout_notification_t layout_notification_func)
{
    switch(active_layout) {
    	case LAYOUT_REQUEST:
    		(*layout_notification_func)(si->lines[active_layout].request_title, 
                    si->lines[active_layout].request_body, NOTIFICATION_REQUEST);
            remove_runnable( &handle_confirm_timeout );
    		break;
    	case LAYOUT_REQUEST_NO_ANIMATION:
    		(*layout_notification_func)(si->lines[active_layout].request_title,
                    si->lines[active_layout].request_body, NOTIFICATION_REQUEST_NO_ANIMATION);
            remove_runnable( &handle_confirm_timeout );
    		break;
    	case LAYOUT_CONFIRM_ANIMATION:
    		(*layout_notification_func)(si->lines[active_layout].request_title, 
                    si->lines[active_layout].request_body, NOTIFICATION_CONFIRM_ANIMATION);
    		post_delayed( &handle_confirm_timeout, (void*)si, CONFIRM_TIMEOUT_MS );
    		break;
    	case LAYOUT_CONFIRMED:
    		(*layout_notification_func)(si->lines[active_layout].request_title, 
                    si->lines[active_layout].request_body, NOTIFICATION_CONFIRMED);
    		remove_runnable( &handle_confirm_timeout );
    		break;
    	default:
    		assert(0);
    };

}

/*
 *  confirm() - user confirmation function interface 
 *
 *  INPUT - 
 *  	type - type of button request to send to host
 *      *request_title - title of confirm message
 *      *request_body - body of confirm message
 *  OUTPUT -
 */
bool confirm(ButtonRequestType type, const char *request_title, const char *request_body, ...)
{
	button_request_acked = false;

	va_list vl;
	va_start(vl, request_body);
	char strbuf[body_char_width()+1];
	vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
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
 *  confirm_with_custom_layout() - user confirmation function interface that allows custom layout notification
 *
 *  INPUT - 
 *      layout_notification_func - custom layout notification
 *      type - type of button request to send to host
 *      *request_title - title of confirm message
 *      *request_body - body of confirm message
 *  OUTPUT -
 */
bool confirm_with_custom_layout(layout_notification_t layout_notification_func, ButtonRequestType type, 
    const char *request_title, const char *request_body, ...)
{
    button_request_acked = false;

    va_list vl;
    va_start(vl, request_body);
    char strbuf[body_char_width()+1];
    vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
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
 * confirm_without_button_request() - user confirmation function interface without button request
 *
 * INPUT -
 *       *request_title -
 *       *request_body -
 * OUTPUT -
 *      true/false - status
 */
bool confirm_without_button_request(const char *request_title, const char *request_body, ...)
{
	button_request_acked = true;

	va_list vl;
	va_start(vl, request_body);
	char strbuf[body_char_width()+1];
	vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
	va_end(vl);

	return confirm_helper(request_title, strbuf, &layout_standard_notification);
}

/*
 * review()
 *
 * INPUT - 
 * 		type -
 *      *request_title
 *      *request_body
 * OUTPUT - 
 *      true/false - status
 *  
 */
bool review(ButtonRequestType type, const char *request_title, const char *request_body, ...)
{
	button_request_acked = false;

	va_list vl;
	va_start(vl, request_body);
	char strbuf[body_char_width()+1];
	vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
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
 * review_without_button_request() - user review function interface without button request
 *
 * INPUT -
 *      *request_title
 *      *request_body
 * OUTPUT -
 *      true/false - status
 *
 */
bool review_without_button_request(const char *request_title, const char *request_body, ...)
{
	button_request_acked = true;

	va_list vl;
	va_start(vl, request_body);
	char strbuf[body_char_width()+1];
	vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
	va_end(vl);

	confirm_helper(request_title, strbuf, &layout_standard_notification);
	return true;
}

/*
 * confirm_helper()  - function for confirm
 *
 * INPUT - 
 *      *request_title - title of confirm message
 *      *request_body - body of confirm message
 *      *layout_notification_func - layout notification function to use to display confirm message
 * OUTPUT - 
 */
bool confirm_helper(const char *request_title, const char *request_body, layout_notification_t layout_notification_func)
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

    memset((void*)&state_info, 0, sizeof(state_info));
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

    keepkey_button_set_on_press_handler( &handle_screen_press, (void*)&state_info );
    keepkey_button_set_on_release_handler( &handle_screen_release, (void*)&state_info );

    cur_layout = LAYOUT_INVALID;
    while(1) {
        cm_disable_interrupts();
    	new_layout = state_info.active_layout;
    	new_ds = state_info.display_state;
        cm_enable_interrupts();

        /* Listen for tiny messages */
        tiny_msg = check_for_tiny_msg(msg_tiny_buf);

        switch(tiny_msg) {
        	case MessageType_MessageType_ButtonAck:
        		button_request_acked = true;
        		break;
            case MessageType_MessageType_Cancel:
            case MessageType_MessageType_Initialize:
			    if (tiny_msg == MessageType_MessageType_Initialize) {
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

        if(new_ds == FINISHED) {
            ret_stat = true;
            break; /* confirmation done.  Exiting function */
        }

        if(cur_layout != new_layout) {
            swap_layout(new_layout, &state_info, layout_notification_func);
            cur_layout = new_layout;
        }

#if DEBUG_LINK
        if(debug_decided && button_request_acked) {
        	break; /* confirmation done via debug link.  Exiting function */
        }
#endif

        display_refresh();
        animate();
    }

confirm_helper_exit:

    keepkey_button_set_on_press_handler( NULL, NULL );
    keepkey_button_set_on_release_handler( NULL, NULL );

    return(ret_stat);
}

/*
 * confirm_cipher() -
 *
 * INPUT - 
 *      encrypt -
 *      key - 
 * OUTPUT - 
 *      true/false - status
 */
bool confirm_cipher(bool encrypt, const char *key)
{
    bool ret_stat;

	if(encrypt) {
		ret_stat = confirm(ButtonRequestType_ButtonRequest_Other,
			"Encrypt Key Value", key);
	} else {
		ret_stat = confirm(ButtonRequestType_ButtonRequest_Other,
			"Decrypt Key Value", key);
	}

    return(ret_stat);
}

/*
 * confirm_encrypt_msg()
 *
 * INPUT -
 *      *msg - 
 *      signing - 
 * OUTPUT - 
 *      true/false - status
 */
bool confirm_encrypt_msg(const char *msg, bool signing)
{
    bool ret_stat;

	if(signing) {
		ret_stat = confirm(ButtonRequestType_ButtonRequest_ProtectCall,
			"Encrypt and Sign Message", msg);
    } else {
		 ret_stat = confirm(ButtonRequestType_ButtonRequest_ProtectCall,
			"Encrypt Message", msg);
    }

    return(ret_stat);
}

/*
 * confirm_decrypt_msg()
 *
 * INPUT -
 *      *msg -
 *      *address -
 * OUTPUT -
 *      true/false - status
 *
 */
bool confirm_decrypt_msg(const char *msg, const char *address)
{
    bool ret_stat;

	if(address) {
		ret_stat = confirm(ButtonRequestType_ButtonRequest_Other,
                "Decrypted Signed Message", msg);
    } else {
		ret_stat = confirm(ButtonRequestType_ButtonRequest_Other,
                "Decrypted Message", msg);
    }

    return(ret_stat);
}

/*
 * confirm_transaction_output()
 *
 * INPUT -
 *      *amount - amount to send
 *      *to - who to send to
 * OUTPUT -
 *      true/false - status
 *
 */
bool confirm_transaction_output(const char *amount, const char *to)
{
	return confirm_with_custom_layout(&layout_transaction_notification,
        ButtonRequestType_ButtonRequest_ConfirmOutput, amount, to);
}

/*
 * confirm_load_device()
 *
 * INPUT -
 *      is_node -
 * OUTPUT -
 *      true/false - status
 *
 */
bool confirm_load_device(bool is_node)
{
    bool ret_stat;

	if(is_node) {
		ret_stat = confirm(ButtonRequestType_ButtonRequest_ProtectCall,
		    	"Import Private Key", "Importing is not recommended unless you understand the risks. Do you want to import private key?");
    } else {
		ret_stat = confirm(ButtonRequestType_ButtonRequest_ProtectCall,
		    	"Import Recovery Sentence", "Importing is not recommended unless you understand the risks. Do you want to import recovery sentence?");
    }

    return(ret_stat);
}

/*
 * confirm_address()
 *
 * INPUT -
 *      *request_title - title for confirm message
 *      *address - address to display both as string and in QR
 * OUTPUT -
 *      true/false - status
 *
 */
bool confirm_address(const char *desc, const char *address)
{
    return confirm_with_custom_layout(&layout_address_notification,
        ButtonRequestType_ButtonRequest_Address, desc, address);
}

/*
 * confirm_sign_identity()
 *
 * INPUT -
 *      *identity - identity information from protocol buffer
 *      *challenge - challenge string
 * OUTPUT -
 *      true/false - status
 *
 */
bool confirm_sign_identity(const IdentityType *identity, const char *challenge)
{
    return confirm(ButtonRequestType_ButtonRequest_ProtectCall,
        "Import Recovery Sentence", "Importing is not recommended unless you understand the risks. Do you want to import recovery sentence?");
}

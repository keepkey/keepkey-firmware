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

#include "pin_sm.h"
#include "fsm.h"

#include <stdbool.h>

#include <layout.h>
#include <messages.h>
#include <rand.h>
#include <storage.h>
#include <timer.h>

/*******************  variables *************************************/
/* Flag whether pin was canceled by init msg */
static bool pin_canceled_by_init = false;

/*******************FUNCTION Definitions  ****************************/

/*
 * send_pin_request() - send USB request for PIN entry over USB port 
 *
 * INPUT  - 
 *      type -pin request type 
 * OUTPUT - 
 *      none
 *
 *
 */
static void send_pin_request(PinMatrixRequestType type)
{
	PinMatrixRequest resp;
	memset(&resp, 0, sizeof(PinMatrixRequest));
	resp.has_type = true;
	resp.type = type;
	msg_write(MessageType_MessageType_PinMatrixRequest, &resp);
}

/*
 * wait_for_pin_ack() - capture PIN entry from user over USB port 
 *
 * INPUT - 
 *      *pin_info -  pointer to PIN info
 * OUTPUT -  none
 *
 */
static void wait_for_pin_ack(PINInfo *pin_info)
{
	/* Listen for tiny messages */
	uint8_t msg_tiny_buf[64];
	uint16_t tiny_msg = wait_for_tiny_msg(msg_tiny_buf);

	/* Check for standard pin matrix ack */
	if(tiny_msg == MessageType_MessageType_PinMatrixAck) {
		pin_info->pin_ack_msg = PIN_ACK_RECEIVED;
		PinMatrixAck *pma = (PinMatrixAck *)msg_tiny_buf;

		strcpy(pin_info->pin, pma->pin);
	}

	/* Check for pin tumbler ack */
	//TODO:Implement PIN tumbler

	/* Check for cancel or initialize messages */
	if(tiny_msg == MessageType_MessageType_Cancel) {
		pin_info->pin_ack_msg = PIN_ACK_CANCEL;
    }

	if(tiny_msg == MessageType_MessageType_Initialize) {
		pin_info->pin_ack_msg = PIN_ACK_CANCEL_BY_INIT;
    }
}

/*
 * run_pin_state() - request and receive PIN from user over USB port
 *
 * INPUT
 *      *pin_state - state of request
 *      *pin_info - buffer for user PIN
 *
 */
static void run_pin_state(PINState *pin_state, PINInfo *pin_info)
{
	switch(*pin_state){

		/* Send PIN request */
		case PIN_REQUEST:
			if(pin_info->type)
				send_pin_request(pin_info->type);
			*pin_state = PIN_WAITING;
			break;

		/* Wait for a PIN */
		case PIN_WAITING:
			wait_for_pin_ack(pin_info);
			if(pin_info->pin_ack_msg != PIN_ACK_WAITING)
				*pin_state = PIN_FINISHED;
			break;
	}
}

/*
 * randomize_pin() - scramble the user input to prevent keystroke sniffing
 *
 * INPUT -
 *      pin - keyboard matrix 
 * OUTPUT - none
 *
 */
static void randomize_pin(char pin[])
{
	for (uint16_t i = 0; i < 10000; i++) {
		uint32_t j = random32() % strlen(pin);
		uint32_t k = random32() % strlen(pin);
		char temp = pin[j];
		pin[j] = pin[k];
		pin[k] = temp;
	}
}

/*
 * decode_pin() - decode user PIN entry
 * 
 * INPUT -
 *      randomized_pin -
 *      *pin_info - 
 * OUTPUT -
 *      none
 *
 */
static void decode_pin(char randomized_pin[], PINInfo *pin_info)
{
	for (uint8_t i = 0; i < strlen(pin_info->pin); i++) {
		uint8_t j = pin_info->pin[i] - '0';

		if(0 <= j < strlen(randomized_pin)) {
			pin_info->pin[i] = randomized_pin[j];
        } else {
			pin_info->pin[i] = 'X';
        }
	}
}

/*
 * pin_request() - request user for PIN entry
 *
 * INPUT - 
 *      *prompt - pointer to user text
 * OUTPUT - 
 *      true/false - status
 *
 */
static bool pin_request(const char *prompt, PINInfo *pin_info)
{
	bool ret = false;
	pin_canceled_by_init = false;
	PINState pin_state = PIN_REQUEST;

	/* Init and randomize pin matrix */
	char pin_matrix[] = "123456789";
	randomize_pin(pin_matrix);

	/* Show layout */
	layout_pin(prompt, pin_matrix);

	/* Run SM */
	while(1) {
		run_pin_state(&pin_state, pin_info);

		if(pin_state == PIN_FINISHED) {
			break;
        }
	}

	/* Check for PIN cancel */
	if (pin_info->pin_ack_msg != PIN_ACK_RECEIVED) {
		if(pin_info->pin_ack_msg == PIN_ACK_CANCEL_BY_INIT) {
			pin_canceled_by_init = true;
        }
		cancel_pin(FailureType_Failure_PinCancelled, "PIN Cancelled");
	} else {
		/* Decode PIN */
		decode_pin(pin_matrix, pin_info);

		ret = true;
	}

	return (ret);
}

/*
 * pin_protect() - Authenticate user PIN for device access.
 *
 * INPUT - none
 * OUTPUT - none
 *
 */
bool pin_protect()
{
	bool ret = false;
	PINInfo pin_info;

	if(storage_has_pin()) {
#if 1  /* TODO : which implementation is prefered */
	    uint32_t wait = 0;
		/* Check for PIN fails */
		if(wait = storage_get_pin_fails())
		{
			//TODO:Have Philip check logic
			if(wait > 2)
			{
				layout_standard_notification("Wrong PIN Entered", "Please wait ...", NOTIFICATION_INFO);
				display_refresh();
			}
			wait = (wait < 32) ? (1u << wait) : 0xFFFFFFFF;
			while (--wait > 0) {
				delay_ms(1000);
			}
		}
#else
        /* TODO : alternate implementation for above */
	    uint32_t pin_failed_delay = 0;
        uint8_t layout_str[50];

        /* install progressively longer wait period as PIN failed attempts increases */
        if(pin_failed_delay = storage_get_pin_fails()) {

			if((pin_failed_delay > PIN_FAIL_DELAY_START) && (pin_failed_delay <= MAX_PIN_FAIL_ATTEMPTS )) {

                if(pin_failed_delay < MAX_PIN_FAIL_ATTEMPTS ) {

                    /* display warning before the last PIN entry */
                    if(pin_failed_delay == MAX_PIN_FAIL_ATTEMPTS - 1) {
                        sprintf(layout_str, "Warning: last attempt for PIN authentication (%d / %d)",
                                pin_failed_delay, MAX_PIN_FAIL_ATTEMPTS);
				        layout_standard_notification(layout_str, 
                                "Device will lock up if the PIN is incorrect...", NOTIFICATION_INFO);
				        display_refresh();
                    } else {
                        sprintf(layout_str, "Wait %d seconds for PIN entry", pin_failed_delay * 5);
				        layout_standard_notification("Incorrect PIN Warning", layout_str, NOTIFICATION_INFO);
				        display_refresh();
                    }

                    pin_failed_delay *= 5;  /* install 5 sec delay for each failed attempts */

                } else {
                    /* Max failed attempts reached.  Lock the system */
                    sprintf(layout_str, "Max PIN Failed Attempts Reached (%d)!!!", MAX_PIN_FAIL_ATTEMPTS);
				    layout_standard_notification("Max Incorrect PIN Failed Attempts Reached", 
                     "Device is locked for safty", NOTIFICATION_INFO);
				    display_refresh();
                    for(;;);
                }
			} else {
                /* no need to install delay for first 2 failure attempts */
			    pin_failed_delay = 1;
            }

            /* force delay for PIN entry */
			while (--pin_failed_delay > 0) {
				delay_ms(ONE_SEC);
			}
		}
#endif

		/* Set request type */
		pin_info.type = PinMatrixRequestType_PinMatrixRequestType_Current;

		/* Get PIN */
		if(pin_request("Enter Your PIN", &pin_info))
		{
			/* authenticate user PIN */
			if (storage_is_pin_correct(pin_info.pin))
			{
				session_cache_pin(pin_info.pin);
				storage_reset_pin_fails();
				ret = true;
			}
			else
			{
				storage_increase_pin_fails();
				fsm_sendFailure(FailureType_Failure_PinInvalid, "Invalid PIN");
			}
		}
		else
			fsm_sendFailure(FailureType_Failure_PinCancelled, "PIN Cancelled");
	} else {
		ret = true;
    }

	return (ret);
}

/*
 * pin_protect_cached() - get state of pin protection
 *
 * INPUT - none
 * OUTPUT -
 *      true/false - status
 *
 */
bool pin_protect_cached(void)
{
	if(session_is_pin_cached()) {
		return (true);
    } else {
		return (pin_protect());
    }
}

/*
 * change_pin() - process PIN change
 * 
 * INPUT - none
 * OUTPUT - 
 *      true/false - status
 *
 */
bool change_pin(void)
{
	bool ret = false;
	PINInfo pin_info_first, pin_info_second;

	/* Set request types */
	pin_info_first.type = 	PinMatrixRequestType_PinMatrixRequestType_NewFirst;
	pin_info_second.type = 	PinMatrixRequestType_PinMatrixRequestType_NewSecond;

	if(pin_request("Enter New PIN", &pin_info_first)) {
		if(pin_request("Re-Enter New PIN", &pin_info_second)) {
			if (strcmp(pin_info_first.pin, pin_info_second.pin) == 0) {
				storage_set_pin(pin_info_first.pin);
				ret = true;
			}
		}
	}
	return ret;
}

/*
 * cancel_pin() - process pin cancellation 
 *
 * INPUT -
 *      code
 *      *text
 * OUTPUT - 
 */
void cancel_pin(FailureType code, const char *text)
{
	if(pin_canceled_by_init) {
		call_msg_initialize_handler();
    } else {
		call_msg_failure_handler(code, text);
    }
	pin_canceled_by_init = false;
}

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

#include <stdbool.h>

#include <keepkey_board.h>
#include <layout.h>
#include <msg_dispatch.h>
#include <rand.h>
#include <storage.h>
#include <timer.h>
#include <stdio.h>

#include "pin_sm.h"
#include "fsm.h"
#include "app_layout.h"

/* === Private Variables =================================================== */

/* Holds random PIN matrix */
static char pin_matrix[PIN_BUF] = "XXXXXXXXX";

/* === Variables =========================================================== */

extern bool reset_msg_stack;

/* === Private Functions =================================================== */

/*
 * send_pin_request() - Send USB request for PIN entry over USB port
 *
 * INPUT
 *     - type: pin request type
 * OUTPUT
 *     none
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
 * wait_for_pin_ack() - Capture PIN entry from user over USB port
 *
 * INPUT
 *     - pin_info: PIN information
 * OUTPUT
 *     none
 */
static void check_for_pin_ack(PINInfo *pin_info)
{
    /* Listen for tiny messages */
    uint8_t msg_tiny_buf[MSG_TINY_BFR_SZ];
    uint16_t tiny_msg;

    tiny_msg = check_for_tiny_msg(msg_tiny_buf);

    switch(tiny_msg)
    {
        case MessageType_MessageType_PinMatrixAck:
            pin_info->pin_ack_msg = PIN_ACK_RECEIVED;
            PinMatrixAck *pma = (PinMatrixAck *)msg_tiny_buf;

            strlcpy(pin_info->pin, pma->pin, PIN_BUF);
            break;

        case MessageType_MessageType_Cancel :   /* Check for cancel or initialize messages */
            pin_info->pin_ack_msg = PIN_ACK_CANCEL;
            break;

        case MessageType_MessageType_Initialize:
            pin_info->pin_ack_msg = PIN_ACK_CANCEL_BY_INIT;
            break;

#if DEBUG_LINK

        case MessageType_MessageType_DebugLinkGetState:
            call_msg_debug_link_get_state_handler((DebugLinkGetState *)msg_tiny_buf);
            break;
#endif

        case MSG_TINY_TYPE_ERROR :
        default:
            break;
    }
}

/*
 * run_pin_state() - Request and receive PIN from user over USB port
 *
 * INPUT
 *     - pin_state: state of request
 *     - pin_info: buffer for user PIN
 */
static void run_pin_state(PINState *pin_state, PINInfo *pin_info)
{
    switch(*pin_state)
    {

        /* Send PIN request */
        case PIN_REQUEST:
            if(pin_info->type)
            {
                send_pin_request(pin_info->type);
            }

            pin_info->pin_ack_msg = PIN_ACK_WAITING;
            *pin_state = PIN_WAITING;
            break;

        /* Wait for a PIN */
        case PIN_WAITING:
            check_for_pin_ack(pin_info);

            if(pin_info->pin_ack_msg != PIN_ACK_WAITING)
            {
                *pin_state = PIN_FINISHED;
            }

            break;

        case PIN_FINISHED:
        case PIN_ACK:
        default:
            break;
    }
}

/*
 * check_pin_input() - Make sure that PIN is at least one digit and a char from 1 to 9
 *
 * INPUT -
 *     - pin_info: PIN information
 * OUTPUT -
 *      true/false whether PIN input is correct format
 */
static bool check_pin_input(PINInfo *pin_info)
{
    bool ret = true;

    /* Check that PIN is at least 1 digit and no more than 9 */
    if(!(strlen(pin_info->pin) >= 1 && strlen(pin_info->pin) <= 9))
    {
        ret = false;
    }

    /* Check that PIN char is a digit from 1 to 9 */
    for(uint8_t i = 0; i < strlen(pin_info->pin); i++)
    {
        uint8_t num = pin_info->pin[i] - '0';

        if(num < 1 || num > 9)
        {
            ret = false;
        }
    }

    return ret;
}

/*
 * decode_pin() - Decode user PIN entry
 *
 * INPUT
 *     - pin_info: PIN information
 * OUTPUT
 *     none
 */
static void decode_pin(PINInfo *pin_info)
{
    for(uint32_t i = 0; i < strlen(pin_info->pin); i++)
    {
        int32_t j = pin_info->pin[i] - '1';

        if(j >= 0 && (uint32_t)j < strlen(pin_matrix))
        {
            pin_info->pin[i] = pin_matrix[j];
        }
        else
        {
            pin_info->pin[i] = 'X';
        }
    }
}

/*
 * pin_request() - Request user for PIN entry
 *
 * INPUT
 *     - prompt: prompt to show user along with PIN matrix
 * OUTPUT -
 *     true/false of whether PIN was received
 */
static bool pin_request(const char *prompt, PINInfo *pin_info)
{
    bool ret = false;
    reset_msg_stack = false;
    PINState pin_state = PIN_REQUEST;

    /* Init and randomize pin matrix */
    strlcpy(pin_matrix, "123456789", PIN_BUF);
    random_permute(pin_matrix, 9);

    /* Show layout */
    layout_pin(prompt, pin_matrix);

    /* Run SM */
    while(1)
    {
        animate();
        display_refresh();

        run_pin_state(&pin_state, pin_info);

        if(pin_state == PIN_FINISHED)
        {
            break;
        }
    }

    /* Check for PIN cancel */
    if(pin_info->pin_ack_msg != PIN_ACK_RECEIVED)
    {
        if(pin_info->pin_ack_msg == PIN_ACK_CANCEL_BY_INIT)
        {
            reset_msg_stack = true;
        }

        fsm_sendFailure(FailureType_Failure_PinCancelled, "PIN Cancelled");
    }
    else
    {
        if(check_pin_input(pin_info))
        {
            /* Decode PIN */
            decode_pin(pin_info);
            ret = true;
        }
        else
        {
            fsm_sendFailure(FailureType_Failure_PinCancelled,
                            "PIN must be at least 1 digit consisting of numbers from 1 to 9");
        }
    }

    /* Clear PIN matrix */
    strlcpy(pin_matrix, "XXXXXXXXX", PIN_BUF);

    return (ret);
}

/* === Functions =========================================================== */


/*
 * pin_protect() - Authenticate user PIN for device access
 *
 * INPUT
 *     - prompt: prompt to show user along with PIN matrix
 * OUTPUT
 *     true/false of whether PIN was correct
 */
bool pin_protect(char *prompt)
{
    PINInfo pin_info;
    char warn_msg_fmt[MEDIUM_STR_BUF];
    uint32_t failed_cnts = 0, wait = 0;
    bool ret = false, pre_increment_cnt_flg = true;

    if(storage_has_pin())
    {

        /* Check for prior PIN failed attempts and apply exponentially longer delay for
         * each subsequent failed attempts */
        if((failed_cnts = storage_get_pin_fails()))
        {
            if(failed_cnts > 2)
            {
                wait = (failed_cnts < 32) ? (1u << failed_cnts) : 0xFFFFFFFF;

                /* snprintf: 36 + 10 (%u) + 1 (NULL) = 47 */
                snprintf(warn_msg_fmt, MEDIUM_STR_BUF, "Previous PIN Failures: Wait %u Seconds",
                         wait);
                layout_warning(warn_msg_fmt);

                while(--wait > 0)
                {
                    delay_ms_with_callback(ONE_SEC, &animating_progress_handler, 20);
                }
            }
        }

        /* Set request type */
        pin_info.type = PinMatrixRequestType_PinMatrixRequestType_Current;

        /* Get PIN */
        if(pin_request(prompt, &pin_info))
        {

            /* preincrement the failed counter before authentication*/
            storage_increase_pin_fails();
            pre_increment_cnt_flg = (failed_cnts >= storage_get_pin_fails());

            /* authenticate user PIN */
            if(storage_is_pin_correct(pin_info.pin) && !pre_increment_cnt_flg)
            {
                session_cache_pin(pin_info.pin);
                storage_reset_pin_fails();
                ret = true;
            }
            else
            {
                fsm_sendFailure(FailureType_Failure_PinInvalid, "Invalid PIN");
            }
        } /* else - PIN entry has been canceled by the user */

    }
    else
    {
        ret = true;
    }

    return (ret);
}

/*
 * pin_protect_cached() - Prompt for PIN only if it is not already cached
 *
 * INPUT
 *     none
 * OUTPUT -
 *     true/false of whether PIN was correct
 */
bool pin_protect_cached(void)
{
    if(session_is_pin_cached())
    {
        return (true);
    }
    else
    {
        return (pin_protect("Enter Your PIN"));
    }
}

/*
 * change_pin() - process PIN change
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false of whether PIN was successfully changed
 */
bool change_pin(void)
{
    bool ret = false;
    PINInfo pin_info_first, pin_info_second;

    /* Set request types */
    pin_info_first.type =   PinMatrixRequestType_PinMatrixRequestType_NewFirst;
    pin_info_second.type =  PinMatrixRequestType_PinMatrixRequestType_NewSecond;

    if(pin_request("Enter New PIN", &pin_info_first))
    {
        if(pin_request("Re-Enter New PIN", &pin_info_second))
        {
            if(strcmp(pin_info_first.pin, pin_info_second.pin) == 0)
            {
                storage_set_pin(pin_info_first.pin);
                ret = true;
            }
            else
            {
                fsm_sendFailure(FailureType_Failure_ActionCancelled, "PIN change failed");
            }
        }
    }

    return ret;
}

/* === Debug Functions =========================================================== */

#if DEBUG_LINK
/*
 * get_pin_matrix() - Gets randomized PIN matrix
 *
 * INPUT
 *     none
 * OUTPUT
 *     randomized PIN
 */
const char *get_pin_matrix(void)
{
    return pin_matrix;
}
#endif

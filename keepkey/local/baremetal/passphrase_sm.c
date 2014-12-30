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

#include "passphrase_sm.h"
#include "protect.h"
#include "fsm.h"

#include <stdbool.h>

#include <layout.h>
#include <messages.h>
#include <rand.h>
#include <storage.h>
#include <timer.h>


//====================== CONSTANTS, TYPES, AND MACROS =========================

/*
 * State for Passphrase SM
 */
typedef enum
{
    PASSPHRASE_REQUEST,
	PASSPHRASE_WAITING,
	PASSPHRASE_ACK,
	PASSPHRASE_FINISHED
} PassphraseState;

/*
 * While waiting for a passphrase ack, these are the types of messages we expect to
 * see.
 */
typedef enum
{
	PASSPHRASE_ACK_WAITING,
    PASSPHRASE_ACK_RECEIVED,
	PASSPHRASE_ACK_CANCEL_BY_INIT,
	PASSPHRASE_ACK_CANCEL
} PassphraseAckMsg;

/*
 * Contains passphrase received info
 */
typedef struct
{
	PassphraseAckMsg passphrase_ack_msg;
	char passphrase[51];
} PassphraseInfo;

//=============================== VARIABLES ===================================

/*
 * Flag whether passphrase was canceled by init msg
 */
static bool passphrase_canceled_by_init = false;

//====================== PRIVATE FUNCTION DECLARATIONS ========================

static void send_passphrase_request(void)
{
	PassphraseRequest resp;
	memset(&resp, 0, sizeof(PassphraseRequest));
	msg_write(MessageType_MessageType_PassphraseRequest, &resp);
}

static void wait_for_passphrase_ack(PassphraseInfo *passphrase_info)
{
	/* Listen for tiny messages */
	uint8_t msg_tiny_buf[64];
	uint16_t tiny_msg = wait_for_tiny_msg(msg_tiny_buf);

	/* Check for standard passphrase ack */
	if(tiny_msg == MessageType_MessageType_PassphraseAck)
	{
		passphrase_info->passphrase_ack_msg = PASSPHRASE_ACK_RECEIVED;
		PassphraseAck *ppa = (PassphraseAck *)msg_tiny_buf;

		strcpy(passphrase_info->passphrase, ppa->passphrase);
	}

	/* Check for passphrase tumbler ack */
	//TODO:Implement passphrase tumbler

	/* Check for cancel or initialize messages */
	if(tiny_msg == MessageType_MessageType_Cancel)
		passphrase_info->passphrase_ack_msg = PASSPHRASE_ACK_CANCEL;

	if(tiny_msg == MessageType_MessageType_Initialize)
		passphrase_info->passphrase_ack_msg = PASSPHRASE_ACK_CANCEL_BY_INIT;
}

static void run_passphrase_state(PassphraseState *passphrase_state, PassphraseInfo *passphrase_info)
{
	switch(*passphrase_state){

		/* Send passphrase request */
		case PASSPHRASE_REQUEST:
			send_passphrase_request();
			*passphrase_state = PASSPHRASE_WAITING;
			break;

		/* Wait for a passphrase */
		case PASSPHRASE_WAITING:
			wait_for_passphrase_ack(passphrase_info);
			if(passphrase_info->passphrase_ack_msg != PASSPHRASE_ACK_WAITING)
				*passphrase_state = PASSPHRASE_FINISHED;
			break;
	}
}

static bool passphrase_request(PassphraseInfo *passphrase_info)
{
	bool ret = false;
	passphrase_canceled_by_init = false;
	PassphraseState passphrase_state = PASSPHRASE_REQUEST;

	/* Run SM */
	while(1)
	{
		run_passphrase_state(&passphrase_state, passphrase_info);

		if(passphrase_state == PASSPHRASE_FINISHED)
			break;
	}

	/* Check for passphrase cancel */
	if (passphrase_info->passphrase_ack_msg == PASSPHRASE_ACK_RECEIVED)
		ret = true;
	else
		if(passphrase_info->passphrase_ack_msg == PASSPHRASE_ACK_CANCEL_BY_INIT)
			passphrase_canceled_by_init = true;

	return ret;
}

//=============================== FUNCTIONS ===================================

bool passphrase_protect()
{
	bool ret = false;
	PassphraseInfo passphrase_info;

	if(storage_get_passphrase_protected() && !session_isPassphraseCached())
	{
		/* Get passphrase and cache */
		if(passphrase_request(&passphrase_info))
		{
			session_cachePassphrase(passphrase_info.passphrase);
			ret = true;
		}
	}
	else
		ret = true;

	return ret;
}

void cancel_passphrase(FailureType code, const char *text)
{
	if(passphrase_canceled_by_init)
		call_msg_initialize_handler();
	else
		call_msg_failure_handler(code, text);

	passphrase_canceled_by_init = false;
}

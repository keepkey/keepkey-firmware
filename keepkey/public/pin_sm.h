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
 * @brief General confirmation state machine
 */

#ifndef PIN_SM_H
#define PIN_SM_H

#include <stdbool.h>
#include <interface.h>

/***************** #defines ********************************/
#define PIN_FAIL_DELAY_START    2
#define MAX_PIN_FAIL_ATTEMPTS   32

/***************** typedefs and enums **********************/

/* State for PIN SM */
typedef enum {
    PIN_REQUEST,
	PIN_WAITING,
	PIN_ACK,
	PIN_FINISHED
} PINState;

/* While waiting for a PIN ack, these are the types of messages we expect to see.  */
typedef enum {
	PIN_ACK_WAITING,
    PIN_ACK_RECEIVED,
	PIN_ACK_CANCEL_BY_INIT,
	PIN_ACK_CANCEL
} PINAckMsg;

/* Contains PIN received info */
typedef struct {
	PinMatrixRequestType type;
	PINAckMsg pin_ack_msg;
	char pin[10];
} PINInfo;
 
/***************** Function Declarations *******************/

bool pin_protect();
bool pin_protect_cached();
bool change_pin(void);
void cancel_pin(FailureType code, const char *text);

#endif

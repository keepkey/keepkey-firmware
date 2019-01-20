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

#ifndef PIN_SM_H
#define PIN_SM_H

#include "keepkey/transport/interface.h"

#include <stdbool.h>

#define PIN_BUF sizeof(((PinMatrixAck *)NULL)->pin)

#define PIN_FAIL_DELAY_START    2
#define MAX_PIN_FAIL_ATTEMPTS   32

/// State for PIN SM.
typedef enum {
	PIN_REQUEST,
	PIN_WAITING,
	PIN_ACK,
	PIN_FINISHED
} PINState;

/// While waiting for a PIN ack, these are the types of messages we expect to see.
typedef enum {
	PIN_ACK_WAITING,
	PIN_ACK_RECEIVED,
	PIN_ACK_CANCEL_BY_INIT,
	PIN_ACK_CANCEL
} PINAckMsg;

/// PIN received info.
typedef struct {
	PinMatrixRequestType type;
	PINAckMsg pin_ack_msg;
	char pin[PIN_BUF];
} PINInfo;

/// Authenticate user PIN for device access.
/// \param prompt Text to show user along with PIN matrix.
/// \returns true iff the PIN was correct.
bool pin_protect(const char *prompt);

/// Prompt for a PIN if uncached or "Pin Caching" Policy set to false.
/// \returns true iff the pin has been correctly authenticated.
bool pin_protect_txsign(void);

/// Prompt for PIN only if it is not already cached.
/// \returns true iff the pin was correct (or already cached).
bool pin_protect_cached(void);

/// Prompt for PIN regardless of whether it was cached
/// \returns true iff the pin was correct (or the device does not
///          require a pin).
bool pin_protect_uncached(void);

/// Process a PIN change.
/// \returns true iff the PIN was successfully changed.
bool change_pin(void);

#if DEBUG_LINK
/// Gets randomized PIN matrix.
const char *get_pin_matrix(void);
#endif

#endif

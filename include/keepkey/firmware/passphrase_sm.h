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

#ifndef PASSPHRASE_SM_H
#define PASSPHRASE_SM_H


#include "keepkey/transport/interface.h"

#include <stdbool.h>


#define PASSPHRASE_BUF sizeof(((PassphraseAck *)NULL)->passphrase)


/* State for Passphrase SM */
typedef enum {
    PASSPHRASE_REQUEST,
	PASSPHRASE_WAITING,
	PASSPHRASE_ACK,
	PASSPHRASE_FINISHED
} PassphraseState;

/* While waiting for a passphrase ack, these are the types of messages we expect to
 * see.
 */
typedef enum {
	PASSPHRASE_ACK_WAITING,
    PASSPHRASE_ACK_RECEIVED,
	PASSPHRASE_ACK_CANCEL_BY_INIT,
	PASSPHRASE_ACK_CANCEL
} PassphraseAckMsg;

/* Contains passphrase received info */
typedef struct {
	PassphraseAckMsg passphrase_ack_msg;
	char passphrase[PASSPHRASE_BUF];
} PassphraseInfo;


bool passphrase_protect(void);

#endif

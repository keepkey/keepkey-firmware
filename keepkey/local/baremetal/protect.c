/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#include <keepkey_board.h>
#include "protect.h"
#include "storage.h"
#include "messages.h"
#include "fsm.h"
#include "util.h"
#include "debug.h"

bool protectPassphrase(void)
{
    return true;
    /*
	if (!storage.has_passphrase_protection || !storage.passphrase_protection || session_isPassphraseCached()) {
		return true;
	}

	PassphraseRequest resp;
	memset(&resp, 0, sizeof(PassphraseRequest));
	msg_write(MessageType_MessageType_PassphraseRequest, &resp);


	layoutDialogSwipe(DIALOG_ICON_INFO, NULL, NULL, NULL, "Please enter your", "passphrase using", "the computer's", "keyboard.", NULL, NULL);

	bool result;
	for (;;) {
		usbPoll();
		if (msg_tiny_id == MessageType_MessageType_PassphraseAck) {
			msg_tiny_id = 0xFFFF;
			PassphraseAck *ppa = (PassphraseAck *)msg_tiny;
			session_cachePassphrase(ppa->passphrase);
			result = true;
			break;
		}
		if (msg_tiny_id == MessageType_MessageType_Cancel || msg_tiny_id == MessageType_MessageType_Initialize) {
			if (msg_tiny_id == MessageType_MessageType_Initialize) {
				fsm_msgInitialize((Initialize *)msg_tiny);
			}
			msg_tiny_id = 0xFFFF;
			result = false;
			break;
		}
	}
	usbTiny(0);
	layoutHome();
	return result;
        */
}

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

#include <string.h>
#include <stdio.h>

#include <bip39.h>
#include <keepkey_board.h>
#include <layout.h>
#include <msg_dispatch.h>
#include <storage.h>

#include "recovery_cypher.h"
#include "fsm.h"
#include "pin_sm.h"
#include "home_sm.h"

void recovery_cypher_init(bool passphrase_protection, bool pin_protection, const char *language, const char *label) {
	if (pin_protection && !change_pin()) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, "PIN change failed");
		go_home();
		return;
	}

	storage_set_passphrase_protected(passphrase_protection);
	storage_setLanguage(language);
	storage_setLabel(label);

	next_character();
}

void next_character(void) {
  CharacterRequest resp;
  memset(&resp, 0, sizeof(CharacterRequest));
  msg_write(MessageType_MessageType_CharacterRequest, &resp);
}
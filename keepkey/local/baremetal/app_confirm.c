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
#include <usb_driver.h>

#include "app_confirm.h"
#include "app_layout.h"
#include "qr_encode.h"

/******************** Static/Global variables *************************/

/******************** Static Function Declarations ********************/

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
    char title[CONFIRM_SIGN_IDENTITY_TITLE], body[CONFIRM_SIGN_IDENTITY_BODY];

    /* Format protocol */
    if (identity->has_proto && identity->proto[0])
    {
        strlcpy(title, identity->proto, sizeof(title));
        strupr(title);
        strlcat(title, " login to: ", sizeof(title));
    }
    else
    {
        strlcpy(title, "Login to: ", sizeof(title));
    }

    /* Format host and port */
    if (identity->has_host && identity->host[0])
    {
        strlcpy(body, "host: ", sizeof(body));
        strlcat(body, identity->host, sizeof(body));
        if (identity->has_port && identity->port[0])
        {
            strlcat(body, ":", sizeof(body));
            strlcat(body, identity->port, sizeof(body));
        }
        strlcat(body, "\n", sizeof(body));
    }
    else
    {
        body[0] = 0;
    }

    /* Format user */
    if (identity->has_user && identity->user[0]) {
        strlcat(body, "user: ", sizeof(body));
        strlcat(body, identity->user, sizeof(body));
        strlcat(body, "\n", sizeof(body));
    }

    /* Format challenge */
    if(strlen(challenge) != 0)
    {
        strlcat(body, challenge, sizeof(body));
    }

    return confirm(ButtonRequestType_ButtonRequest_ProtectCall, title, body);
}

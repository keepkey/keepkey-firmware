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

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <libopencm3/stm32/flash.h>

#include <interface.h>
#include <keepkey_board.h>
#include <memory.h>
#include <messages.h>


#include <usb_driver.h>
#include <usb_flash.h>

void handler_initialize(Initialize* msg);
void handler_ping(Ping* msg);
void handler_update(FirmwareUpdate* msg);
void usb_write_pb(void* msg, MessageType id);

/**
 * Performance / metrics counters.
 */
typedef struct 
{
    uint16_t invalid_usb_header_ct;
    uint16_t invalid_msg_type_ct;
    uint16_t invalid_offset_ct;
    uint16_t usb_tx_ct;
    uint16_t usb_tx_err_ct;
} Stats;

typedef enum 
{
    UPDATE_NOT_STARTED,
    UPDATE_STARTED,
    UPDATE_COMPLETE
} FirmwareUpdateState;

static FirmwareUpdateState update_state = UPDATE_NOT_STARTED;

/**
 * Generic message handler callback type.
 */
typedef void (*message_handler_t)(void* msg_struct);

/**
 * Structure to map incoming messages to handler functions.
 */

static const MessagesMap_t MessagesMap[] = {
	// in messages
	{'i', MessageType_MessageType_Initialize,		Initialize_fields,	(message_handler_t)(handler_initialize)},
	{'i', MessageType_MessageType_Ping,			Ping_fields,		(message_handler_t)(handler_ping)},
	{'i', MessageType_MessageType_FirmwareUpdate,		FirmwareUpdate_fields,	(message_handler_t)(handler_update)},
	{'o', MessageType_MessageType_Features,		        Features_fields,	NULL},
	{'o', MessageType_MessageType_Success,		        Success_fields,		NULL},
	{'o', MessageType_MessageType_Failure,		        Failure_fields,		NULL},
        {0,0,0,0}
};

/**
 * Stats counters.
 */
static Stats stats;

bool is_update_complete(void)
{
    return false;
    return update_state == UPDATE_COMPLETE;
}

bool usb_flash_firmware(void)
{

    layout_standard_notification("Firmware Updating...", "Erasing flash...");
    display_refresh();

    flash_unlock();
    flash_erase(FLASH_CONFIG);
    flash_erase(FLASH_APP);

    /*
     * Send out an unsolicited announcement to trigger the host side of the USB bus to recognize 
     * the device.
     */
    layout_standard_notification("Firmware Updating...", "Programming...");
    display_refresh();
    msg_init(MessagesMap);
    usb_init();

    /*
     * NOTE: After this point the timing requirements for usb_poll are fairly tight during the initial enumeration process.  Don't call display_refresh until the first packets start arriving.
     */

    while(!is_update_complete())
    {
        usb_poll();
    }
    flash_lock();

    layout_standard_notification("Firmware Update Complete", "Reset device to continue.");
    display_refresh();
    return true;
}


void send_success(const char *text)
{
    Success s;
    memset(&s, 0, sizeof(s));

    if (text) {
        s.has_message = true;
        strlcpy(s.message, text, sizeof(s.message));
    }
    msg_write(MessageType_MessageType_Success, &s);
}

void send_failure(FailureType code, const char *text)
{
    Failure f;
    memset(&f, 0, sizeof(f));

    f.has_code = true;
    f.code = code;
    if (text) {
        f.has_message = true;
        strlcpy(f.message, text, sizeof(f.message));
    }
    msg_write(MessageType_MessageType_Failure, &f);
}


void handler_update(FirmwareUpdate* msg) 
{
    update_state = UPDATE_STARTED;
send_success(NULL);
return;




    uint32_t app_flash_start = flash_sector_map[FLASH_APP_SECTOR_FIRST].start;
    uint32_t app_flash_end = flash_sector_map[FLASH_APP_SECTOR_LAST].start + 
        flash_sector_map[FLASH_APP_SECTOR_LAST].len;
    uint32_t app_flash_size = app_flash_end - app_flash_start;

    /*
    if(msg->offset > app_flash_size)
    {
        ++stats.invalid_offset_ct;
        send_failure(FailureType_Failure_UnexpectedMessage, "Offset too large");
        return;
    }
    */

    static uint32_t offset = 0;
    //uint32_t offset = msg->offset + app_flash_start;
    uint32_t size = msg->payload.size;

    if( (offset + size) < app_flash_end)
    {
    	if(size > 0)
    	{
            uint32_t x = offset + app_flash_start;
        //            flash_write(FLASH_APP, offset, size, msg->payload.bytes);
        //
    	}
        send_success(NULL);
        offset += size;

    } else {
        ++stats.invalid_offset_ct;
        send_failure(FailureType_Failure_UnexpectedMessage, "Upload overflow");
        return;
    }

    if(msg->has_final && msg->final == true)
    {
        update_state = UPDATE_COMPLETE;
        flash_lock();
        send_success("Upload complete");
    } 
}

void handler_ping(Ping* msg) 
{
    (void)msg;
}

void handler_initialize(Initialize* msg) 
{
    assert(msg != NULL);

    Features f;
    memset(&f, 0, sizeof(f));

    f.has_bootloader_mode = true;
    f.bootloader_mode = true; 
    f.has_major_version = true;
    f.major_version = BOOTLOADER_MAJOR_VERSION;
    f.minor_version= BOOTLOADER_MINOR_VERSION;
    f.patch_version = BOOTLOADER_PATCH_VERSION;

    msg_write(MessageType_MessageType_Features, &f);
}


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

#include "interface.h"
#include "keepkey_board.h"
#include "memory.h"
#include "messages.h"


#include "usb_driver.h"
#include "usb_flash.h"

void send_failure(FailureType code, const char *text);
void handler_initialize(Initialize* msg);
void handler_ping(Ping* msg);
void handler_erase(FirmwareErase* msg);
void raw_handler_upload(uint8_t *msg, uint32_t msg_size, uint32_t frame_length);
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
    UPLOAD_NOT_STARTED,
    UPLOAD_STARTED,
    UPLOAD_COMPLETE
} FirmwareUploadState;

static FirmwareUploadState upload_state = UPLOAD_NOT_STARTED;

/**
 * Generic message handler callback type.
 */
typedef void (*message_handler_t)(void* msg_struct);

/**
 * Structure to map incoming messages to handler functions.
 */

static const MessagesMap_t MessagesMap[] = {
	// in messages
	{'i', MessageType_MessageType_Initialize,		Initialize_fields,		(message_handler_t)(handler_initialize)},
	{'i', MessageType_MessageType_Ping,				Ping_fields,			(message_handler_t)(handler_ping)},
	{'i', MessageType_MessageType_FirmwareErase,	FirmwareErase_fields,	(message_handler_t)(handler_erase)},
	{'o', MessageType_MessageType_Features,			Features_fields,		NULL},
	{'o', MessageType_MessageType_Success,			Success_fields,			NULL},
	{'o', MessageType_MessageType_Failure,			Failure_fields,			NULL},

	{0,0,0,0}
};

static const RawMessagesMap_t RawMessagesMap[] = {
	{'i', MessageType_MessageType_FirmwareUpload, (message_handler_t)(raw_handler_upload)},

	{0,0,0}
};

/**
 * Stats counters.
 */
static Stats stats;

/*
 * Configuration variables.
 */
#define FIRMWARE_HEADER_SIZE	256

bool is_update_complete(void)
{
    return upload_state == UPLOAD_COMPLETE;
}

bool usb_flash_firmware(void)
{
	layout_warning("Firmware Update Mode");

    /*
     * Init message map, failure function, and usb callback
     */
    msg_map_init(MessagesMap, MESSAGE_MAP);
    msg_map_init(RawMessagesMap, RAW_MESSAGE_MAP);
    msg_failure_init(&send_failure);
    msg_init();

    /*
     * Init USB
     */
    usb_init();

    while(!is_update_complete())
    {
        usb_poll();

        animate();
        display_refresh();
    }

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

void handler_erase(FirmwareErase* msg)
{
	if(confirm("Verify Backup Before Upgrade", "Before upgrading your firmware, confirm that you have access to the backup of your recovery sentence."))
	{
		layout_loading(FLASHING_ANIM);
		force_animation_start();

		animate();
		display_refresh();

		flash_unlock();
		flash_erase(FLASH_CONFIG);
		flash_erase(FLASH_APP);

		send_success("Firmware Erased");
	}
}

void raw_handler_upload(uint8_t *msg, uint32_t msg_size, uint32_t frame_length)
{
	const uint32_t app_flash_start = flash_sector_map[FLASH_APP_SECTOR_FIRST].start;
	const uint32_t app_flash_end = flash_sector_map[FLASH_APP_SECTOR_LAST].start +
		flash_sector_map[FLASH_APP_SECTOR_LAST].len;
	const uint32_t app_flash_size = app_flash_end - app_flash_start;

	static uint32_t flash_offset;
	static uint32_t upload_pos;

	/*
	 * Start firmware upload
	 */
	if(upload_state == UPLOAD_NOT_STARTED)
	{
		upload_state = UPLOAD_STARTED;
		flash_offset = 0;
		upload_pos = 0;

		/*
		 * On first USB segment of upload we have to account for added data for protocol buffers
		 * which we will ignore since it is not being parsed out for us
		 */
		msg_size -= 4;
		msg = (uint8_t*)(msg + 4);
	}

	/*
	 * Incement upload postion
	 */
	upload_pos += msg_size;

	/*
	 * Process firmware upload
	 */
	if(upload_state == UPLOAD_STARTED)
	{
		if(upload_pos - msg_size < FIRMWARE_HEADER_SIZE)
		{
			/*
			 * TODO: Write 256B header to flash for each 64 byte pass (USB_SEGMENT_SIZE) so that
			 * after firmware is upload we can check signatures
			 */
		}

		if(upload_pos > FIRMWARE_HEADER_SIZE)
		{
			if( (flash_offset + msg_size) < app_flash_end)
			{
				if(upload_pos - FIRMWARE_HEADER_SIZE < msg_size)
				{
					uint32_t adj_msg_size = upload_pos - FIRMWARE_HEADER_SIZE;
					flash_write(FLASH_APP, flash_offset, adj_msg_size, msg + (msg_size - adj_msg_size));
					flash_offset += upload_pos - FIRMWARE_HEADER_SIZE;
				}
				else
				{
					flash_write(FLASH_APP, flash_offset, msg_size, msg);
					flash_offset += msg_size;
				}
			} else {
				++stats.invalid_offset_ct;
				send_failure(FailureType_Failure_FirmwareError, "Upload overflow");
			}
		}

		/*
		 * Finish firmware update
		 */
		if (upload_pos >= frame_length - 4)
		{
			flash_lock();
			send_success("Upload complete");
			upload_state = UPLOAD_COMPLETE;
		}
	}
}

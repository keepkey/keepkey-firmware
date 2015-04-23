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

#ifndef USB_FLASH_H
#define USB_FLASH_H

#include <stdbool.h>
#include <stdint.h>

/*** Defines ***/
#define UPLOAD_STATUS_FREQUENCY		1024
#define PROTOBUF_FIRMWARE_PADDING	4

#define SHA256_DIGEST_STR_LEN ((SHA256_DIGEST_LENGTH * 2) + 1)
#define BYTE_AS_HEX_STR_LEN (2 + 1)

/*** Enums ***/
typedef enum 
{
    UPLOAD_NOT_STARTED,
    UPLOAD_STARTED,
    UPLOAD_COMPLETE,
    UPLOAD_ERROR
} FirmwareUploadState;

/*** Typedefs ***/

/* Stats counters */
typedef struct 
{
    uint16_t invalid_usb_header_ct;
    uint16_t invalid_msg_type_ct;
    uint16_t invalid_offset_ct;
    uint16_t usb_tx_ct;
    uint16_t usb_tx_err_ct;
} Stats;

/* Generic message handler callback type*/
typedef void (*message_handler_t)(void* msg_struct); 


/*** Function Declarations ***/ 
bool usb_flash_firmware(void);
static void sav_storage_in_ram(ConfigFlash *cfg_ptr);
bool flash_write_n_lock(Allocation group, size_t offset, size_t len, uint8_t* dataPtr);
void send_success(const char *text);
void send_failure(FailureType code, const char *text);
void handler_initialize(Initialize* msg);
void handler_ping(Ping* msg);
void handler_erase(FirmwareErase* msg);
void raw_handler_upload(uint8_t *msg, uint32_t msg_size, uint32_t frame_length);
void usb_write_pb(void* msg, MessageType id);

#endif

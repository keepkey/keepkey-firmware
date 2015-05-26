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

#ifndef USB_FLASH_H
#define USB_FLASH_H

/* === Includes ============================================================ */

#include <stdbool.h>
#include <stdint.h>

/* === Defines ============================================================= */

#define RESP_INIT(TYPE) TYPE resp; memset(&resp, 0, sizeof(TYPE));

#define UPLOAD_STATUS_FREQUENCY		    1024
#define PROTOBUF_FIRMWARE_HASH_START    2
#define PROTOBUF_FIRMWARE_START	        38

/* === Typedefs ============================================================ */

typedef enum 
{
    UPLOAD_NOT_STARTED,
    UPLOAD_STARTED,
    UPLOAD_COMPLETE,
    UPLOAD_ERROR
} FirmwareUploadState;

/* Generic message handler callback type */
typedef void (*message_handler_t)(void* msg_struct); 

/* === Functions =========================================================== */

bool usb_flash_firmware(void);
void send_success(const char *text);
void send_failure(FailureType code, const char *text);
void handler_initialize(Initialize* msg);
void handler_ping(Ping* msg);
void handler_erase(FirmwareErase* msg);
void raw_handler_upload(uint8_t *msg, uint32_t msg_size, uint32_t frame_length);
#if DEBUG_LINK
void handler_debug_link_get_state(DebugLinkGetState *msg);
void handler_debug_link_stop(DebugLinkStop *msg);
void handler_debug_link_fill_config(DebugLinkFillConfig *msg);
#endif

#endif
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

#include <keepkey_led.h>
#include <keepkey_display.h>
#include <layout.h>
#include <memory.h>

#include <messages.pb.h>
#include <types.pb.h>
#include <pb_decode.h>
#include <pb_encode.h>

#include <usb_driver.h>
#include <usb_flash.h>

/*
 * Max message decode size for use in statically allocating space for incoming
 * protobuf packets.  This would ideally key off a nanopb struct size, but there 
 * appears to not be a good way to determin the max sized structure.
 */
#define MAX_DECODE_SIZE 512


void handler_initialize(Initialize* msg);
void handler_ping(Ping* msg);
void handler_update(FirmwareUpdate* msg);
void usb_write_pb(const pb_field_t* fields, void* msg, MessageType id);

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

#pragma pack(1)
/**
 * This structure is derived from the Trezor protocol.  Note that the values come in as big endian, so
 * they'll need to be swapped.
 */

/**
 * USB Header coming in from the pc/libusb
 */
typedef struct
{
    uint8_t hid_type;  // This is always '?'
} UsbHeader;

typedef struct
{
    /* 
     * Not sure what these are for.  They are derived from the Trezor code. I think they denote the first
     * USB segment in a message, in the case where multiple USB segments are sent. 
     */
    uint8_t pre1;
    uint8_t pre2;

    /* Protobuf ID */
    uint16_t id;    

    /* Length of the following message */
    uint32_t len;

} TrezorFrameHeader;

typedef struct 
{
    UsbHeader usb_header;
    TrezorFrameHeader header;
    uint8_t contents[0];
} TrezorFrame;

typedef struct
{
    TrezorFrame frame;
    uint8_t buffer[MAX_DECODE_SIZE];
} TrezorFrameBuffer;

#pragma pack()

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
typedef struct 
{
    MessageType         type;
    message_handler_t   handler;
    const pb_field_t    *fields;
} DispatchTable;

static const DispatchTable dispatch_table[] = 
{
    { MessageType_MessageType_Initialize,       (message_handler_t)handler_initialize,     Initialize_fields }, 
    { MessageType_MessageType_Ping,             (message_handler_t)handler_ping,           Ping_fields },  
    { MessageType_MessageType_FirmwareUpdate,   (message_handler_t)handler_update,         FirmwareUpdate_fields }, 
};

/**
 * Stats counters.
 */
static Stats stats;

const DispatchTable* type_to_dispatch(MessageType type)
{
    size_t i;
    for(i=0; i < sizeof(dispatch_table) / sizeof(dispatch_table[0]); i++)
    {
        if(type == dispatch_table[i].type)
        {
            return &dispatch_table[i];
        }
    }

    return NULL;
}

void dispatch(const DispatchTable *entry, uint8_t *msg, uint32_t msg_size)
{
    static uint8_t decode_buffer[MAX_DECODE_SIZE];

    pb_istream_t stream = pb_istream_from_buffer(msg, msg_size);

    bool status = pb_decode(&stream, entry->fields, decode_buffer);
    if (status) {
        entry->handler(decode_buffer);
    } 

    /* TODO: Handle error response */
}

void handle_usb_rx(UsbMessage *msg)
{
    TrezorFrame *frame = (TrezorFrame*)(msg->message);
    if(frame->usb_header.hid_type != '?')
    {
        ++stats.invalid_usb_header_ct;
        return;
    }

    /*
     * Byte swap in place.
     */
    frame->header.id = __builtin_bswap16(frame->header.id);
    frame->header.len = __builtin_bswap32(frame->header.len);

    if(! frame->header.id < MessageType_MessageType_LAST) 
    {
        ++stats.invalid_msg_type_ct;
        return;
    }
    
    const DispatchTable *entry = type_to_dispatch(frame->header.id);
    dispatch(entry, frame->contents, frame->header.len);
}

bool is_update_complete(void)
{
    return update_state == UPDATE_COMPLETE;
}

bool usb_flash_firmware(void)
{

//    usb_set_rx_callback(handle_usb_rx);
    usb_init();
    while(1) usb_poll();


    layout_standard_notification("Firmware Updating...", "Erasing flash...");
    display_refresh();
    flash_unlock();
    flash_erase(FLASH_APP);


    /*
     * Send out an unsolicited announcement to trigger the host side of the USB bus to recognize 
     * the device.
     */
    layout_standard_notification("Firmware Updating...", "Programming...");
    display_refresh();

    while(!is_update_complete())
    {
        display_refresh();
        usbPoll();
    }
    flash_lock();

    layout_standard_notification("Firmware Update Complete", "Reset device to continue.");
    display_refresh();
    return true;
}

void handler_update(FirmwareUpdate* msg) 
{
    update_state = UPDATE_STARTED;

    uint32_t app_flash_start = flash_sector_map[FLASH_APP_SECTOR_FIRST].start;
    uint32_t app_flash_end = flash_sector_map[FLASH_APP_SECTOR_LAST].start + 
        flash_sector_map[FLASH_APP_SECTOR_LAST].len;
    uint32_t app_flash_size = app_flash_end - app_flash_start;

    if(msg->offset > app_flash_size)
    {
        ++stats.invalid_offset_ct;
    }

    uint32_t offset = msg->offset + app_flash_start;
    uint32_t size = msg->payload.size;

    if( (offset + size) < app_flash_end)
    {
        if(size > 0)
        {
            flash_write(FLASH_APP, offset, size, msg->payload.bytes);
        }
    } else {
        ++stats.invalid_offset_ct;
    }

    if(msg->has_final && msg->final == true)
    {
        update_state = UPDATE_COMPLETE;
        flash_lock();
    } 
}

void handler_ping(Ping* msg) 
{
    (void)msg;
}

void handler_initialize(Initialize* msg) 
{
    (void)msg;

    Features f;
    memset(&f, 0, sizeof(f));

    f.has_bootloader_mode = true;
    f.bootloader_mode = true; 
    f.has_major_version = true;
    f.major_version = BOOTLOADER_MAJOR_VERSION;
    f.minor_version= BOOTLOADER_MINOR_VERSION;
    f.patch_version = BOOTLOADER_PATCH_VERSION;

    usb_write_pb(Features_fields, &f, MessageType_MessageType_Features);
}

void usb_write_pb(const pb_field_t* fields, void* msg, MessageType id)
{
    assert(fields != NULL);

    TrezorFrameBuffer framebuf;
    memset(&framebuf, 0, sizeof(framebuf));
    framebuf.frame.usb_header.hid_type = '?';
    framebuf.frame.header.pre1 = '#';
    framebuf.frame.header.pre2 = '#';
    framebuf.frame.header.id = __builtin_bswap16(id);

    pb_ostream_t os = pb_ostream_from_buffer(framebuf.buffer, sizeof(framebuf.buffer));
    bool status = pb_encode(&os, fields, msg);
    assert(status);

    framebuf.frame.header.len = __builtin_bswap32(os.bytes_written);

//    bool ret = usb_tx(&framebuf, sizeof(framebuf.frame) + os.bytes_written);
//    ret ? stats.usb_tx_ct++ : stats.usb_tx_err_ct++;
}


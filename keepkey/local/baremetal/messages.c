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

#include <assert.h>
#include <string.h>

#include <usb_driver.h>

#include "trezor.h"
#include "messages.h"
#include "debug.h"
#include "fsm.h"
#include "util.h"

#include <nanopb.h>
#include <interface.h>


// SimpleSignTx_size is the largest message we operate with
#if MSG_IN_SIZE < SimpleSignTx_size
#error "MSG_IN_SIZE is too small!"
#endif

/**
 * Structure to track diagnostic and monitoring status.
 */
typedef struct
{
    uint16_t runt_packet;
    uint16_t invalid_usb_header;
    uint16_t invalid_msg_type;
    uint16_t unknown_dispatch_entry;
    uint16_t usb_tx;
    uint16_t usb_tx_err;
} MsgStats;

static MsgStats msg_stats;


struct MessagesMap_t {
    char dir; 	// i = in, o = out
    MessageType msg_id;
    const pb_field_t *fields;
    void (*process_func)(void *ptr);
};

static const struct MessagesMap_t MessagesMap[] = {
	// in messages
	{'i', MessageType_MessageType_Initialize,		Initialize_fields,	(void (*)(void *))fsm_msgInitialize},
	{'i', MessageType_MessageType_Ping,			Ping_fields,		(void (*)(void *))fsm_msgPing},
	{'o', MessageType_MessageType_Features,		        Features_fields,	0},
#if 0
	{'n', 'i', MessageType_MessageType_ChangePin,		ChangePin_fields,	(void (*)(void *))fsm_msgChangePin},
	{'n', 'i', MessageType_MessageType_WipeDevice,		WipeDevice_fields,	(void (*)(void *))fsm_msgWipeDevice},
	{'n', 'i', MessageType_MessageType_FirmwareErase,	FirmwareErase_fields,	(void (*)(void *))fsm_msgFirmwareErase},
	{'n', 'i', MessageType_MessageType_FirmwareUpload,	FirmwareUpload_fields,	(void (*)(void *))fsm_msgFirmwareUpload},
	{'n', 'i', MessageType_MessageType_GetEntropy,		GetEntropy_fields,	(void (*)(void *))fsm_msgGetEntropy},
	{'n', 'i', MessageType_MessageType_GetPublicKey,	GetPublicKey_fields,	(void (*)(void *))fsm_msgGetPublicKey},
	{'n', 'i', MessageType_MessageType_LoadDevice,		LoadDevice_fields,	(void (*)(void *))fsm_msgLoadDevice},
	{'n', 'i', MessageType_MessageType_ResetDevice,		ResetDevice_fields,	(void (*)(void *))fsm_msgResetDevice},
	{'n', 'i', MessageType_MessageType_SignTx,		SignTx_fields,		(void (*)(void *))fsm_msgSignTx},
	{'n', 'i', MessageType_MessageType_SimpleSignTx,	SimpleSignTx_fields,	(void (*)(void *))fsm_msgSimpleSignTx},
//	{'n', 'i', MessageType_MessageType_PinMatrixAck,	PinMatrixAck_fields,	(void (*)(void *))fsm_msgPinMatrixAck},
	{'n', 'i', MessageType_MessageType_Cancel,		Cancel_fields,		(void (*)(void *))fsm_msgCancel},
	{'n', 'i', MessageType_MessageType_TxAck,		TxAck_fields,		(void (*)(void *))fsm_msgTxAck},
	{'n', 'i', MessageType_MessageType_ApplySettings,	ApplySettings_fields,	(void (*)(void *))fsm_msgApplySettings},
//	{'n', 'i', MessageType_MessageType_ButtonAck,		ButtonAck_fields,	(void (*)(void *))fsm_msgButtonAck},
	{'n', 'i', MessageType_MessageType_GetAddress,		GetAddress_fields,	(void (*)(void *))fsm_msgGetAddress},
	{'n', 'i', MessageType_MessageType_EntropyAck,		EntropyAck_fields,	(void (*)(void *))fsm_msgEntropyAck},
	{'n', 'i', MessageType_MessageType_SignMessage,		SignMessage_fields,	(void (*)(void *))fsm_msgSignMessage},
	{'n', 'i', MessageType_MessageType_VerifyMessage,	VerifyMessage_fields,	(void (*)(void *))fsm_msgVerifyMessage},
//	{'n', 'i', MessageType_MessageType_PassphraseAck,	PassphraseAck_fields,	(void (*)(void *))fsm_msgPassphraseAck},
	{'n', 'i', MessageType_MessageType_EstimateTxSize,	EstimateTxSize_fields,	(void (*)(void *))fsm_msgEstimateTxSize},
	{'n', 'i', MessageType_MessageType_RecoveryDevice,	RecoveryDevice_fields,	(void (*)(void *))fsm_msgRecoveryDevice},
	{'n', 'i', MessageType_MessageType_WordAck,		WordAck_fields,		(void (*)(void *))fsm_msgWordAck},
	// out message
	{'n', 'o', MessageType_MessageType_Success,		Success_fields,		0},
	{'n', 'o', MessageType_MessageType_Failure,		Failure_fields,		0},
	{'n', 'o', MessageType_MessageType_Entropy,		Entropy_fields,		0},
	{'n', 'o', MessageType_MessageType_PublicKey,		PublicKey_fields,	0},
.	{'n', 'o', MessageType_MessageType_Features,		Features_fields,	0},
	{'n', 'o', MessageType_MessageType_PinMatrixRequest,	PinMatrixRequest_fields,0},
	{'n', 'o', MessageType_MessageType_TxRequest,		TxRequest_fields,	0},
	{'n', 'o', MessageType_MessageType_ButtonRequest,	ButtonRequest_fields,	0},
	{'n', 'o', MessageType_MessageType_Address,		Address_fields,		0},
	{'n', 'o', MessageType_MessageType_EntropyRequest,	EntropyRequest_fields,	0},
	{'n', 'o', MessageType_MessageType_MessageSignature,	MessageSignature_fields,0},
	{'n', 'o', MessageType_MessageType_PassphraseRequest,	PassphraseRequest_fields,   0},
	{'n', 'o', MessageType_MessageType_TxSize,		TxSize_fields,	    	0},
	{'n', 'o', MessageType_MessageType_WordRequest,		WordRequest_fields,	0},
	// end
#endif
	{0, 0, 0, 0}
};

const struct MessagesMap_t* message_map_entry(MessageType type)
{
    const struct MessagesMap_t *m = MessagesMap;
    while(m->msg_id) {
        if(type == m->msg_id)
        {
            return m;
        }
        ++m;
    }

    return NULL;
}

const pb_field_t *message_fields(MessageType type)
{
    const struct MessagesMap_t *m = MessagesMap;
    while (m->msg_id) {
        if (type == m->msg_id) {
            return m->fields;
        }
        m++;
    }
    return 0;
}

void usb_write_pb(const pb_field_t* fields, const void* msg, MessageType id)
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

    bool ret = usb_tx(&framebuf, sizeof(framebuf.frame) + os.bytes_written);
    ret ? msg_stats.usb_tx++ : msg_stats.usb_tx_err++;
}


bool msg_write(MessageType type, const void *msg_ptr)
{
    const pb_field_t *fields = message_fields(type);
    if (!fields) { // unknown message
        return false;
    }

    usb_write_pb(fields, msg_ptr, type);

    return true;
}

void dispatch(const struct MessagesMap_t* entry, uint8_t *msg, uint32_t msg_size)
{
    static uint8_t decode_buffer[MAX_DECODE_SIZE];

    pb_istream_t stream = pb_istream_from_buffer(msg, msg_size);

    bool status = pb_decode(&stream, entry->fields, decode_buffer);
    if (status) {
        entry->process_func(decode_buffer);
    } else {
        /* TODO: Handle error response */
    }
}


/**
 * Local routine to handle messages incoming from the USB driver.
 *
 * @param msg The incoming usb message, which may be a packet fragment or a
 *      complete message.
 */
void handle_usb_rx(UsbMessage *msg)
{
    assert(msg);
    if(msg->len < sizeof(TrezorFrameHeader))
    {
        ++msg_stats.runt_packet;
        return;
    }
    TrezorFrame *frame = (TrezorFrame*)(msg->message);
    if(frame->usb_header.hid_type != '?')
    {
        ++msg_stats.invalid_usb_header;
        return;
    }

    /*
     * Byte swap in place.
     */
    frame->header.id = __builtin_bswap16(frame->header.id);
    frame->header.len = __builtin_bswap32(frame->header.len);


    const struct MessagesMap_t* entry = message_map_entry(frame->header.id);
    if(entry)
    {
        dispatch(entry, frame->contents, frame->header.len);
    } else {
        ++msg_stats.unknown_dispatch_entry;
    }
}

void msg_init(void)
{
    usb_set_rx_callback(handle_usb_rx);
}


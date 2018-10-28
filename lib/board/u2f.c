/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (C) 2015 Mark Bryars <mbryars@google.com>
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

#include "keepkey/board/u2f.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/u2f_hid.h"
#include "keepkey/board/u2f_types.h"
#include "keepkey/board/usb_driver.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/rand.h"

#ifdef EMULATOR
#  include <assert.h>
#endif
#include <string.h>

#define MIN(a, b) ({ typeof(a) _a = (a); typeof(b) _b = (b); _a < _b ? _a : _b; })

#define debugLog(L, B, T) do{}while(0)
#define debugInt(I) do{}while(0)

// About 1/2 Second according to values used in protect.c
#define U2F_TIMEOUT (800000/2)

// Initialise without a cid
static uint32_t cid = 0;

// We hijack the FIDO U2F protocol to do device communication through signing
// requests.  Authentication messages are distinguished from device transport
// via one of the hardening bits in the key handle derivation path.  This
// ensures that the two are mutually exclusive.
static bool is_hijack = true;

uint32_t next_cid(void)
{
	// extremely unlikely but hey
	do {
		cid = random32();
	} while (cid == 0 || cid == CID_BROADCAST);
	return cid;
}

typedef struct {
	uint8_t buf[57+127*59];
	uint8_t *buf_ptr;
	uint32_t len;
	uint8_t seq;
	uint8_t cmd;
} U2F_ReadBuffer;

U2F_ReadBuffer *reader;

u2f_rx_callback_t u2f_user_rx_callback = NULL;

void u2f_set_rx_callback(u2f_rx_callback_t callback){
    u2f_user_rx_callback = callback;
}

#if DEBUG_LINK
u2f_rx_callback_t u2f_user_debug_rx_callback = NULL;

void u2f_set_debug_rx_callback(u2f_rx_callback_t callback){
    u2f_user_debug_rx_callback = callback;
}
#endif

static u2f_register_callback_t u2f_register_callback = 0;
static u2f_authenticate_callback_t u2f_authenticate_callback = 0;
static u2f_version_callback_t u2f_version_callback = 0;


void u2f_init(u2f_register_callback_t register_cb, u2f_authenticate_callback_t authenticate_cb,
              u2f_version_callback_t version_cb) {
	u2f_register_callback = register_cb;
	u2f_authenticate_callback = authenticate_cb;
	u2f_version_callback = version_cb;

	// Force channel ID initialization
	(void)u2f_get_channel();
}

const uint8_t *u2f_get_channel(void) {
	static uint8_t channel[4] = { 0, 0, 0, 0 };

	// Initialize U2F Transport channel id
	while (memcmp(channel, "\x00\x00\x00\x00", 4) == 0)
		random_buffer(channel, sizeof(channel));

	return channel;
}

void u2fhid_read(char tiny, const U2FHID_FRAME *f)
{
	// Always handle init packets directly
	if (f->init.cmd == U2FHID_INIT) {
		u2fhid_init(f);
		if (tiny && reader && f->cid == cid) {
			// abort current channel
			reader->cmd = 0;
			reader->len = 0;
			reader->seq = 255;
		}
		return;
	}

	if (tiny) {
		// read continue packet
		if (reader == 0 || cid != f->cid) {
			send_u2fhid_error(f->cid, ERR_CHANNEL_BUSY);
			return;
		}

		if ((f->type & TYPE_INIT) && reader->seq == 255) {
			u2fhid_init_cmd(f);
			return;
		}

		if (reader->seq != f->cont.seq) {
			send_u2fhid_error(f->cid, ERR_INVALID_SEQ);
			reader->cmd = 0;
			reader->len = 0;
			reader->seq = 255;
			return;
		}

		// check out of bounds
		if ((reader->buf_ptr - reader->buf) >= (signed) reader->len
			|| (reader->buf_ptr + sizeof(f->cont.data) - reader->buf) > (signed) sizeof(reader->buf))
			return;
		reader->seq++;
		memcpy(reader->buf_ptr, f->cont.data, sizeof(f->cont.data));
		reader->buf_ptr += sizeof(f->cont.data);
		return;
	}

	u2fhid_read_start(f);
}

void u2fhid_init_cmd(const U2FHID_FRAME *f) {
	reader->seq = 0;
	reader->buf_ptr = reader->buf;
	reader->len = MSG_LEN(*f);
	reader->cmd = f->type;
	memcpy(reader->buf_ptr, f->init.data, sizeof(f->init.data));
	reader->buf_ptr += sizeof(f->init.data);
	cid = f->cid;
}

void u2fhid_read_start(const U2FHID_FRAME *f) {
	static U2F_ReadBuffer readbuffer;
	if (f->init.cmd == 0){
		return;
	}
	if (!(f->type & TYPE_INIT)) {
		return;
	}

	// Broadcast is reserved for init
	if (f->cid == CID_BROADCAST || f->cid == 0) {
		send_u2fhid_error(f->cid, ERR_INVALID_CID);
		return;
	}

	if ((unsigned)MSG_LEN(*f) > sizeof(reader->buf)) {
		send_u2fhid_error(f->cid, ERR_INVALID_LEN);
		return;
	}

	reader = &readbuffer;
	u2fhid_init_cmd(f);

	usbTiny(1);
	for(;;) {
		// Do we need to wait for more data
		while ((reader->buf_ptr - reader->buf) < (signed)reader->len) {
			uint8_t lastseq = reader->seq;
			uint8_t lastcmd = reader->cmd;
			int counter = U2F_TIMEOUT;
			while (reader->seq == lastseq && reader->cmd == lastcmd) {
				if (counter-- == 0) {
					// timeout
					send_u2fhid_error(cid, ERR_MSG_TIMEOUT);
					cid = 0;
					reader = 0;
					usbTiny(0);
					return;
				}
				usb_poll();
			}
		}
        usbTiny(0);
		// We have all the data
		switch (reader->cmd) {
		case 0:
			// message was aborted by init
			break;
		case U2FHID_PING:
			u2fhid_ping(reader->buf, reader->len);
			break;
		case U2FHID_MSG:
			u2fhid_msg((APDU *)reader->buf, reader->len);
			break;
		case U2FHID_WINK:
			u2fhid_wink(reader->buf, reader->len);
			break;
		default:
			send_u2fhid_error(cid, ERR_INVALID_CMD);
			break;
		}

		// wait for next commmand/ button press
		reader->cmd = 0;
		reader->seq = 255;

		// U2F hijack packet framing requires conserved cid.
		if (!is_hijack)
			cid = 0;
		reader = 0;
		usbTiny(0);
		return;
	}
}

void u2fhid_ping(const uint8_t *buf, uint32_t len)
{
	debugLog(0, "", "u2fhid_ping");
	send_u2fhid_msg(U2FHID_PING, buf, len);
}

void u2fhid_wink(const uint8_t *buf, uint32_t len)
{
	debugLog(0, "", "u2fhid_wink");
	(void)buf;

	if (len > 0)
		return send_u2fhid_error(cid, ERR_INVALID_LEN);

	(void)review_without_button_request("U2F Wink", "\n;-)");
	layout_home();

	U2FHID_FRAME f;
	memset(&f, 0, sizeof(f));
	f.cid = cid;
	f.init.cmd = U2FHID_WINK;
	f.init.bcntl = 0;
	queue_u2f_pkt(&f);
}

void u2fhid_init(const U2FHID_FRAME *in)
{
	const U2FHID_INIT_REQ *init_req = (const U2FHID_INIT_REQ *)&in->init.data;
	U2FHID_FRAME f;
	U2FHID_INIT_RESP resp;

	debugLog(0, "", "u2fhid_init");

	if (in->cid == 0) {
		send_u2fhid_error(in->cid, ERR_INVALID_CID);
		return;
	}

	memset(&f, 0, sizeof(f));
	f.cid = in->cid;
	f.init.cmd = U2FHID_INIT;
	f.init.bcnth = 0;
	f.init.bcntl = U2FHID_INIT_RESP_SIZE;

	memcpy(resp.nonce, init_req->nonce, sizeof(init_req->nonce));
	resp.cid = in->cid == CID_BROADCAST ? next_cid() : in->cid;
	resp.versionInterface = U2FHID_IF_VERSION;
	resp.versionMajor = MAJOR_VERSION;
	resp.versionMinor = MINOR_VERSION;
	resp.versionBuild = PATCH_VERSION;
	resp.capFlags = CAPFLAG_WINK;
	memcpy(&f.init.data, &resp, sizeof(resp));

	queue_u2f_pkt(&f);
}

void queue_u2f_pkt(const U2FHID_FRAME *u2f_pkt)
{
#ifndef EMULATOR
	usb_u2f_tx_helper((uint8_t *) u2f_pkt, HID_RPT_SIZE, ENDPOINT_ADDRESS_U2F_IN);
#else
	assert(false && "U2F transport not supported in the emulator");
#endif
}

void u2fhid_msg(const APDU *a, uint32_t len)
{
	if ((APDU_LEN(*a) + sizeof(APDU)) > len) {
		debugLog(0, "", "BAD APDU LENGTH");
		debugInt(APDU_LEN(*a));
		debugInt(len);
		return;
	}

	if (a->cla != 0) {
		send_u2f_error(U2F_SW_CLA_NOT_SUPPORTED);
		return;
	}

	switch (a->ins) {
		case U2F_REGISTER:
			u2f_register(a);
			break;
		case U2F_AUTHENTICATE:
			u2f_authenticate(a);
			break;
		case U2F_VERSION:
			u2f_version(a);
			break;
		default:
			debugLog(0, "", "u2f unknown cmd");
			send_u2f_error(U2F_SW_INS_NOT_SUPPORTED);
	}
}

void send_u2fhid_msg(const uint8_t cmd, const uint8_t *data, const uint32_t len)
{
	U2FHID_FRAME f;
	uint8_t *p = (uint8_t *)data;
	uint32_t l = len;
	uint32_t psz;
	uint8_t seq = 0;

	// debugLog(0, "", "send_u2fhid_msg");

	memset(&f, 0, sizeof(f));
	f.cid = cid;
	f.init.cmd = cmd;
	f.init.bcnth = len >> 8;
	f.init.bcntl = len & 0xff;

	// Init packet
	psz = MIN(sizeof(f.init.data), l);
	memcpy(f.init.data, p, psz);
	queue_u2f_pkt(&f);
	l -= psz;
	p += psz;

	// Cont packet(s)
	for (; l > 0; l -= psz, p += psz) {
		// debugLog(0, "", "send_u2fhid_msg con");
		memset(&f.cont.data, 0, sizeof(f.cont.data));
		f.cont.seq = seq++;
		psz = MIN(sizeof(f.cont.data), l);
		memcpy(f.cont.data, p, psz);
		queue_u2f_pkt(&f);
	}

#if 0
	if (data + len != p) {
		debugLog(0, "", "send_u2fhid_msg is bad");
		debugInt(data + len - p);
	}
#endif
}

void send_u2fhid_error(uint32_t fcid, uint8_t err)
{
	U2FHID_FRAME f;

	memset(&f, 0, sizeof(f));
	f.cid = fcid;
	f.init.cmd = U2FHID_ERROR;
	f.init.bcntl = 1;
	f.init.data[0] = err;
	queue_u2f_pkt(&f);
}

void u2f_version(const APDU *a)
{
	if (APDU_LEN(*a) != 0) {
		debugLog(0, "", "u2f version - badlen");
		send_u2f_error(U2F_SW_WRONG_LENGTH);
		return;
	}

	// INCLUDES SW_NO_ERROR
	static const uint8_t version_response[] = {'U', '2', 'F',  '_',
						   'V', '2', 0x90, 0x00};
	debugLog(0, "", "u2f version");
	send_u2f_msg(version_response, sizeof(version_response));
}

void u2f_register(const APDU *a)
{
	const U2F_REGISTER_REQ *req = (U2F_REGISTER_REQ *)a->data;

	// Validate basic request parameters
	debugLog(0, "", "u2f register");
	if (APDU_LEN(*a) != sizeof(U2F_REGISTER_REQ)) {
		debugLog(0, "", "u2f register - badlen");
		send_u2f_error(U2F_SW_WRONG_LENGTH);
		return;
	}

	if (u2f_register_callback) {
		u2f_register_callback(req);
	} else {
#ifdef EMULATOR
		assert(false && "Emulator does not support FIDO u2f");
#else
		send_u2f_error(U2F_SW_WRONG_DATA);
#endif
	}
}

void u2f_authenticate(const APDU *a)
{
	const U2F_AUTHENTICATE_REQ *req = (U2F_AUTHENTICATE_REQ *)a->data;

	if (APDU_LEN(*a) < 64) { /// FIXME: decent value
		debugLog(0, "", "u2f authenticate - badlen");
		layout_simple_message("SW_WRONG_LENGTH");
		send_u2f_error(U2F_SW_WRONG_LENGTH);
		return;
	}

	if (req->keyHandleLen != KEY_HANDLE_LEN) {
		debugLog(0, "", "u2f auth - bad keyhandle len");
		send_u2f_error(U2F_SW_WRONG_DATA); // error:bad key handle
		return;
	}

	// support auth check only

	if (a->p1 == U2F_AUTH_CHECK_ONLY) {
		debugLog(0, "", "u2f authenticate check");
		layout_simple_message("SW_COND_NOT_SAT");
		// This is a success for a good keyhandle
		// A failed check would have happened earlier
		// error: testof-user-presence is required
		send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
		return;
	}

	if (a->p1 != U2F_AUTH_ENFORCE) {
		debugLog(0, "", "u2f authenticate unknown");
		layout_simple_message("SW_AUTH_ENF");
		// error:bad key handle
		send_u2f_error(U2F_SW_WRONG_DATA);
		return;
	}

	is_hijack = (req->keyHandle[3] & 0x80) == 0;
	if (is_hijack) {
		if (req->keyHandle[2] != 0x00) {
			return;
		}

		uint8_t channel[4];
		memcpy(channel, req->keyHandle + 4, 4);

		// If the message is a brodacast,
		if (memcmp(channel, "\x00\x00\x00\x00", 4) == 0) {
			// ... respond with our version info
			if (u2f_version_callback)
				u2f_version_callback(u2f_get_channel());
			return;
		}

		// Otherwise make sure it's for us
		if (memcmp(channel, u2f_get_channel(), 4) != 0)
			return;

		// unpack keyHandle raw (protobuf) message frame and dispatch
		static UsbMessage m;
		memset(&m, 0, sizeof(m));
		m.len = KEY_HANDLE_LEN - 8; // 8-bytes { total_frames, frame_i, reserved, reserved & 0x3f,
		                            //           channel[0], channel[1], channel[2], channel[3] }
		memcpy(m.message, req->keyHandle + 8, KEY_HANDLE_LEN - 8);

		if ((req->keyHandle[3] & 0x40) == 0x00) {
			if (u2f_user_rx_callback) {
				u2f_user_rx_callback(&m);
			}
#if DEBUG_LINK
		} else {
			if (u2f_user_debug_rx_callback) {
				u2f_user_debug_rx_callback(&m);
			}
#endif
		}
		return;
	}

	if (u2f_authenticate_callback) {
		u2f_authenticate_callback(req);
	} else {
#ifdef EMULATOR
		assert(false && "Emulator does not support FIDO u2f");
#endif
	}
}

void send_u2f_error(const uint16_t err)
{
	uint8_t data[2];
	data[0] = err >> 8 & 0xFF;
	data[1] = err & 0xFF;
	send_u2f_msg(data, 2);
}

void send_u2f_msg(const uint8_t *data, const uint32_t len)
{
	send_u2fhid_msg(U2FHID_MSG, data, len);
}

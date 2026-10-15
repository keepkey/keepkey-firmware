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

#include "keepkey/firmware/u2f.h"

#include "storage.h"
#include "u2f_knownapps.h"

#include "keepkey/board/keepkey_button.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/memcmp_s.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/u2f_hid.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/ctap2.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/u2f/u2f.h"
#include "keepkey/firmware/u2f/u2f_keys.h"
#include "keepkey/rand/rng_health.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/bip39_english.h"
#include "trezor/crypto/ecdsa.h"
#include "trezor/crypto/hmac.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/nist256p1.h"
#include "trezor/crypto/rand.h"

#include <stdio.h>
#include <string.h>

#ifdef EMULATOR
#include <assert.h>
#endif
#include <string.h>

// About 1/2 Second according to values used in protect.c
#define U2F_TIMEOUT (800000 / 2)
#define U2F_OUT_PKT_BUFFER_LEN 130

#define debugLog(L, B, T) \
  do {                    \
  } while (0)
#define debugInt(I) \
  do {              \
  } while (0)

// Initialise without a cid
static uint32_t cid = 0;

#if 0
// Circular Output buffer
static uint32_t u2f_out_start = 0;
static uint32_t u2f_out_end = 0;
static uint8_t u2f_out_packets[U2F_OUT_PKT_BUFFER_LEN][HID_RPT_SIZE];
#endif

#define U2F_PUBKEY_LEN 65
#define KEY_PATH_LEN 32
#define KEY_HANDLE_LEN (KEY_PATH_LEN + SHA256_DIGEST_LENGTH)
#define KEY_HANDLE_GENERATION_BASE_LEN \
  (U2F_APPID_SIZE + KEY_PATH_LEN + PASSKEY_CREDENTIAL_GENERATION_SIZE)

// Derivation path is m/U2F'/r'/r'/r'/r'/r'/r'/r'/r'
#define KEY_PATH_ENTRIES (KEY_PATH_LEN / sizeof(uint32_t))

// Defined as UsbSignHandler.BOGUS_APP_ID_HASH
// in
// https://github.com/google/u2f-ref-code/blob/master/u2f-chrome-extension/usbsignhandler.js#L118
#define BOGUS_APPID "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// Auth/Register request state machine
typedef enum {
  INIT = 0,
  AUTH = 10,
  AUTH_PASS = 11,
  REG = 20,
  REG_PASS = 21
} U2F_STATE;

static U2F_STATE last_req_state = INIT;

typedef struct {
  uint8_t reserved;
  uint8_t appId[U2F_APPID_SIZE];
  uint8_t chal[U2F_CHAL_SIZE];
  uint8_t keyHandle[KEY_HANDLE_LEN];
  uint8_t pubKey[U2F_PUBKEY_LEN];
} U2F_REGISTER_SIG_STR;

typedef struct {
  uint8_t appId[U2F_APPID_SIZE];
  uint8_t flags;
  uint8_t ctr[4];
  uint8_t chal[U2F_CHAL_SIZE];
} U2F_AUTHENTICATE_SIG_STR;

static uint32_t dialog_timeout = 0;

/* User presence is a press and release that starts after the prompt is drawn
 * (Trezor's button.YesUp): the button must be seen up, then down, then up.
 * Steps: 0 waits for up, 1 for down, 2 for the release. */
static uint8_t presence_step = 0;

static bool presenceReleased(void) {
  const bool want_up = presence_step != 1;
  if (keepkey_button_up() == want_up) presence_step++;
  if (presence_step < 3) return false;
  presence_step = 0;
  return true;
}

uint32_t next_cid(void) {
  // extremely unlikely but hey
  do {
    cid = random32();
  } while (cid == 0 || cid == CID_BROADCAST);
  return cid;
}

// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html#message--and-packet-structure
// states the following:
// With a packet size of 64 bytes (max for full-speed devices), this means that
// the maximum message payload length is 64 - 7 + 128 * (64 - 5) = 7609 bytes.
#define U2F_MAXIMUM_PAYLOAD_LENGTH 7609
typedef struct {
  uint8_t buf[U2F_MAXIMUM_PAYLOAD_LENGTH];
  uint8_t* buf_ptr;
  uint32_t len;
  uint8_t seq;
  uint8_t cmd;
} U2F_ReadBuffer;

U2F_ReadBuffer* reader;

/* The CTAP2 request being handled, which may wait for a button press while
 * USB keeps polling. Until it answers, nothing may touch the request buffer
 * or move its channel: other frames get CHANNEL_BUSY, and CANCEL or INIT on
 * its channel only flag the cancel. */
static bool ctap_active;
static uint32_t ctap_cid;
static bool ctap_cancelled;

void u2fhid_read(char tiny, const U2FHID_FRAME* f) {
  /* U2F bypasses the protobuf dispatch gate. A new top-level operation,
   * including INIT, must end a previously approved RNG audit too. */
  if (!tiny) fsm_revoke_entropy_audit();

  if (ctap_active) {
    if (f->init.cmd == U2FHID_INIT) {
      if (MSG_LEN(*f) != 8) { /* INIT carries exactly an 8-byte nonce */
        send_u2fhid_error(f->cid, ERR_INVALID_LEN);
        return;
      }
      if (f->cid == ctap_cid) ctap_cancelled = true;
      u2fhid_init(f);
      cid = ctap_cid; /* a new channel allocation must not take this one */
    } else if (f->cid == ctap_cid && (f->type & TYPE_INIT) &&
               f->init.cmd == U2FHID_CANCEL) {
      if (MSG_LEN(*f) == 0)
        ctap_cancelled = true;
      else
        send_u2fhid_error(f->cid, ERR_INVALID_LEN);
    } else {
      send_u2fhid_error(f->cid, ERR_CHANNEL_BUSY);
    }
    return;
  }

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

  /* A setup ceremony waits in the main loop for its next message. A U2F
   * session started now would draw over it and end on the home screen, while
   * a recovery stays armed and keeps taking CharacterAcks with no cipher
   * shown. Answer busy and leave the screen alone. */
  if (!tiny && setup_isArmed()) {
    send_u2fhid_error(f->cid, ERR_CHANNEL_BUSY);
    return;
  }

  if (tiny) {
    // read continue packet
    if (reader == 0 || cid != f->cid) {
      send_u2fhid_error(f->cid, ERR_CHANNEL_BUSY);
      return;
    }

    if ((f->type & TYPE_INIT) && reader->seq == 255) {
      if (reader->cmd == U2FHID_CBOR && f->init.cmd != U2FHID_CANCEL) {
        send_u2fhid_error(f->cid, ERR_CHANNEL_BUSY);
        return;
      }
      if (f->init.cmd == U2FHID_CANCEL && MSG_LEN(*f) != 0) {
        send_u2fhid_error(f->cid, ERR_INVALID_LEN);
        return;
      }
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
    if ((reader->buf_ptr - reader->buf) >= (signed)reader->len ||
        (reader->buf_ptr + sizeof(f->cont.data) - reader->buf) >
            (signed)sizeof(reader->buf))
      return;
    reader->seq++;
    memcpy(reader->buf_ptr, f->cont.data, sizeof(f->cont.data));
    reader->buf_ptr += sizeof(f->cont.data);
    return;
  }

  u2fhid_read_start(f);
}

void u2fhid_init_cmd(const U2FHID_FRAME* f) {
  reader->seq = 0;
  reader->buf_ptr = reader->buf;
  reader->len = MSG_LEN(*f);
  reader->cmd = f->type;
  memcpy(reader->buf_ptr, f->init.data, sizeof(f->init.data));
  reader->buf_ptr += sizeof(f->init.data);
  cid = f->cid;
}

/* Every exit from a U2F session. The request state and any presence progress
 * belong to the prompt this session drew, and layoutHome() removes it, so
 * neither may survive into a later session: a request resent then must be
 * prompted again and needs a fresh press. */
static void u2fhid_session_end(bool msg_tiny) {
  last_req_state = INIT;
  presence_step = 0;
  dialog_timeout = 0;
  cid = 0;
  reader = 0;
  usbTiny(0);
  msg_set_tiny(msg_tiny);
  /* As fsm_msgPing(): never leave an armed recovery behind the home screen. */
  if (setup_isArmedAs(SETUP_RECOVERY)) {
    recovery_cipher_redraw();
  } else {
    layoutHome();
  }
}

/* A normal or debug frame rejected during the session is answered through the
 * failure handler, which redraws the screen (home, the recovery cipher, a
 * signer's abort). Forget the request, so presence is not polled for a prompt
 * that is gone: the host's next retry draws it again, and needs a fresh
 * press. */
static void forgetPromptIfOverdrawn(void) {
  if (!msg_take_tiny_rejection()) return;
  last_req_state = INIT;
  presence_step = 0;
}

/* Initialize and Cancel end a U2F session as they end any other prompt, and
 * are then answered as at top level. A request still being received is
 * dropped, so its sender is told. */
static bool hostEndedSession(bool msg_tiny) {
  const MessageType id = msg_take_tiny_id();
#if DEBUG_LINK
  /* Inspect the active prompt without dispatching a nested workflow. The
   * request has no fields and msg_take_tiny_id() already cleared its buffer. */
  if (id == MessageType_MessageType_DebugLinkGetState) {
    DebugLinkGetState request = {0};
    call_msg_debug_link_get_state_handler(&request);
    return false;
  }
#endif
  if (id != MessageType_MessageType_Initialize &&
      id != MessageType_MessageType_Cancel) {
    return false;
  }
  if ((reader->buf_ptr - reader->buf) < (signed)reader->len) {
    send_u2fhid_error(cid, ERR_CHANNEL_BUSY);
  }
  u2fhid_session_end(msg_tiny);
  if (keepkey_before_message_dispatch(id)) {
    if (id == MessageType_MessageType_Initialize) {
      fsm_msgInitialize(0);
    } else {
      fsm_msgCancel(0);
    }
  }
  return true;
}

void u2fhid_read_start(const U2FHID_FRAME* f) {
  U2F_ReadBuffer readbuffer;
  memzero(&readbuffer, sizeof(readbuffer));

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
  /* Main and debug frames must not be dispatched under the U2F prompt: a
   * nested confirm would replace it, and its held button would then count as
   * U2F presence. Trezor uses one tiny flag for every endpoint. */
  const bool msg_tiny = msg_set_tiny(true);
  /* One left over from an earlier prompt was not sent to this session. */
  msg_take_tiny_id();
  for (;;) {
    // Do we need to wait for more data
    while ((reader->buf_ptr - reader->buf) < (signed)reader->len) {
      uint8_t lastseq = reader->seq;
      uint8_t lastcmd = reader->cmd;
      int counter = U2F_TIMEOUT;
      while (reader->seq == lastseq && reader->cmd == lastcmd) {
        if (counter-- == 0) {
          // timeout
          send_u2fhid_error(cid, ERR_MSG_TIMEOUT);
          u2fhid_session_end(msg_tiny);
          return;
        }
        usbPoll();
        keepkey_idle_clock_sample();
        forgetPromptIfOverdrawn();
        if (hostEndedSession(msg_tiny)) return;
      }
    }

    // We have all the data. Mark the transport ready for an asynchronous
    // CTAPHID_CANCEL while a CTAP2 command waits for user presence.
    uint8_t command = reader->cmd;
    reader->seq = 255;
    switch (command) {
      case 0:
        // message was aborted by init
        break;
      case U2FHID_PING:
        u2fhid_ping(reader->buf, reader->len);
        break;
      case U2FHID_MSG:
        u2fhid_msg((APDU*)reader->buf, reader->len);
        break;
      case U2FHID_CBOR:
        /* A CTAP2 request can interleave on the same channel while a legacy
         * U2F AUTHENTICATE/REGISTER is still pending a button press
         * (last_req_state == AUTH/REG, dialog_timeout still counting down).
         * ctap2_request_user_presence() has its own self-contained button
         * loop and never touches last_req_state/dialog_timeout, so without
         * this reset the button press the user gives for THIS (CTAP2)
         * request could satisfy the wait loop below's stale
         * last_req_state==AUTH/REG check and silently advance the
         * unrelated legacy request to AUTH_PASS/REG_PASS -- approving it
         * with no dialog for it ever having been on screen at press time.
         * Invalidate any pending legacy request once a different command
         * type has interleaved. */
        last_req_state = INIT;
        u2fhid_cbor(reader->buf, reader->len);
        break;
      case U2FHID_CANCEL:
        /* Nothing in flight; u2fhid_read() flags in-flight cancels. */
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
    while (dialog_timeout > 0 && reader->cmd == 0) {
      dialog_timeout--;
      usbPoll();  // may trigger new request
      keepkey_idle_clock_sample();
      forgetPromptIfOverdrawn();
      if (hostEndedSession(msg_tiny)) return;
      if ((last_req_state == AUTH || last_req_state == REG) &&
          presenceReleased()) {
        last_req_state++;
        // standard requires to remember button press for 10 seconds.
        dialog_timeout = 10 * U2F_TIMEOUT;
      }
    }

    if (reader->cmd == 0) {
      u2fhid_session_end(msg_tiny);
      return;
    }
  }
}

void u2fInit(void) {
  ctap2_init();
  usb_set_u2f_rx_callback(u2fhid_read);
}

void u2fhid_ping(const uint8_t* buf, uint32_t len) {
  debugLog(0, "", "u2fhid_ping");
  send_u2fhid_msg(U2FHID_PING, buf, len);
}

void u2fhid_wink(const uint8_t* buf, uint32_t len) {
  debugLog(0, "", "u2fhid_wink");
  (void)buf;

  if (len > 0) return send_u2fhid_error(cid, ERR_INVALID_LEN);

  if (dialog_timeout > 0) dialog_timeout = U2F_TIMEOUT;

  U2FHID_FRAME f;
  memzero(&f, sizeof(f));
  f.cid = cid;
  f.init.cmd = U2FHID_WINK;
  f.init.bcntl = 0;
  queue_u2f_pkt(&f);
}

void u2fhid_init(const U2FHID_FRAME* in) {
  const U2FHID_INIT_REQ* init_req = (const U2FHID_INIT_REQ*)&in->init.data;
  U2FHID_FRAME f;
  U2FHID_INIT_RESP resp;
  memzero(&resp, sizeof(resp));

  debugLog(0, "", "u2fhid_init");

  if (in->cid == 0) {
    send_u2fhid_error(in->cid, ERR_INVALID_CID);
    return;
  }

  memzero(&f, sizeof(f));
  f.cid = in->cid;
  f.init.cmd = U2FHID_INIT;
  f.init.bcnth = 0;
  f.init.bcntl = sizeof(resp);

  memcpy(resp.nonce, init_req->nonce, sizeof(init_req->nonce));
  resp.cid = in->cid == CID_BROADCAST ? next_cid() : in->cid;
  resp.versionInterface = U2FHID_IF_VERSION;
  resp.versionMajor = MAJOR_VERSION;
  resp.versionMinor = MINOR_VERSION;
  resp.versionBuild = PATCH_VERSION;
  resp.capFlags = CAPFLAG_WINK | CAPFLAG_CBOR;
  memcpy(&f.init.data, &resp, sizeof(resp));

  queue_u2f_pkt(&f);
}

#if 0
void queue_u2f_pkt(const U2FHID_FRAME *u2f_pkt)
{
	// debugLog(0, "", "u2f_write_pkt");
	uint32_t next = (u2f_out_end + 1) % U2F_OUT_PKT_BUFFER_LEN;
	if (u2f_out_start == next) {
		debugLog(0, "", "u2f_write_pkt full");
		return; // Buffer full :(
	}
	memcpy(u2f_out_packets[u2f_out_end], u2f_pkt, HID_RPT_SIZE);
	u2f_out_end = next;
}

uint8_t *u2f_out_data(void)
{
	if (u2f_out_start == u2f_out_end)
		return NULL; // No data
	// debugLog(0, "", "u2f_out_data");
	uint32_t t = u2f_out_start;
	u2f_out_start = (u2f_out_start + 1) % U2F_OUT_PKT_BUFFER_LEN;
	return u2f_out_packets[t];
}
#endif

void u2fhid_msg(const APDU* a, uint32_t len) {
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

void u2fhid_cbor(const uint8_t* buf, uint32_t len) {
  static uint8_t response[CTAP2_MAX_RESPONSE_SIZE];
  size_t response_len = 0;
  ctap_active = true;
  ctap_cid = cid;
  ctap_cancelled = false;
  ctap2_set_transport_channel(cid);
  ctap2_handle(buf, len, response, sizeof(response), &response_len);
  cid = ctap_cid;
  send_u2fhid_msg(U2FHID_CBOR, response, response_len);
  ctap_active = false;
}

void send_u2fhid_msg(const uint8_t cmd, const uint8_t* data,
                     const uint32_t len) {
  if (len > U2F_MAXIMUM_PAYLOAD_LENGTH) {
    debugLog(0, "", "send_u2fhid_msg failed");
    return;
  }

  U2FHID_FRAME f;
  uint8_t* p = (uint8_t*)data;
  uint32_t l = len;
  uint32_t psz;
  uint8_t seq = 0;

  // debugLog(0, "", "send_u2fhid_msg");

  memzero(&f, sizeof(f));
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
    memzero(&f.cont.data, sizeof(f.cont.data));
    f.cont.seq = seq++;
    psz = MIN(sizeof(f.cont.data), l);
    memcpy(f.cont.data, p, psz);
    queue_u2f_pkt(&f);
  }

  if (data + len != p) {
    debugLog(0, "", "send_u2fhid_msg is bad");
    debugInt(data + len - p);
  }
}

void send_u2fhid_error(uint32_t fcid, uint8_t err) {
  U2FHID_FRAME f;

  memzero(&f, sizeof(f));
  f.cid = fcid;
  f.init.cmd = U2FHID_ERROR;
  f.init.bcntl = 1;
  f.init.data[0] = err;
  queue_u2f_pkt(&f);
}

void u2f_version(const APDU* a) {
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

const char* words_from_data(const uint8_t* data, int len) {
  if (len > 32) return NULL;

  int mlen = len * 3 / 4;
  static char mnemo[24 * 10];

  int i, j;
  char* p = mnemo;
  for (i = 0; i < mlen; i++) {
    int idx = 0;
    for (j = 0; j < 11; j++) {
      idx <<= 1;
      idx += (data[(i * 11 + j) / 8] & (1 << (7 - ((i * 11 + j) % 8)))) > 0;
    }
    strcpy(p, wordlist[idx]);
    p += strlen(wordlist[idx]);
    *p = (i < mlen - 1) ? ' ' : 0;
    p++;
  }

  return mnemo;
}

static bool getReadableAppId(const uint8_t appid[U2F_APPID_SIZE],
                             const char** appname) {
  for (unsigned int i = 0; i < sizeof(u2f_well_known) / sizeof(U2FWellKnown);
       i++) {
    if (memcmp(appid, u2f_well_known[i].appid, U2F_APPID_SIZE) == 0) {
      *appname = u2f_well_known[i].appname;
      return true;
    }
  }

  // Otherwise use the mnemonic wordlist to invent some human-readable
  // identifier of the first 48 bits.
  *appname = words_from_data(appid, 6);
  return false;
}

static const HDNode* getDerivedNode(const uint32_t* address_n,
                                    size_t address_n_count) {
  static CONFIDENTIAL HDNode node;
  if (!storage_getU2FRoot(&node)) {
    layoutHome();
    debugLog(0, "", "ERR: Device not init");
    return 0;
  }
  if (!address_n || address_n_count == 0) {
    return &node;
  }
  for (size_t i = 0; i < address_n_count; i++) {
    if (hdnode_private_ckd(&node, address_n[i]) == 0) {
      layoutHome();
      debugLog(0, "", "ERR: Derive private failed");
      return 0;
    }
  }
  return &node;
}

static void key_handle_hmac(
    const uint8_t private_key[32], const uint8_t app_id[32],
    const uint8_t key_path[KEY_PATH_LEN],
    const uint8_t generation[PASSKEY_CREDENTIAL_GENERATION_SIZE],
    bool bind_generation, uint8_t output[SHA256_DIGEST_LENGTH]) {
  uint8_t keybase[KEY_HANDLE_GENERATION_BASE_LEN];
  memcpy(keybase, app_id, U2F_APPID_SIZE);
  memcpy(keybase + U2F_APPID_SIZE, key_path, KEY_PATH_LEN);
  size_t keybase_length = U2F_APPID_SIZE + KEY_PATH_LEN;
  if (bind_generation) {
    memcpy(keybase + keybase_length, generation,
           PASSKEY_CREDENTIAL_GENERATION_SIZE);
    keybase_length += PASSKEY_CREDENTIAL_GENERATION_SIZE;
  }
  hmac_sha256(private_key, 32, keybase, keybase_length, output);
  memzero(keybase, sizeof(keybase));
}

bool u2f_key_handle_authenticator_is_valid(
    const uint8_t private_key[32], const uint8_t app_id[32],
    const uint8_t key_handle[64],
    const uint8_t generation[PASSKEY_CREDENTIAL_GENERATION_SIZE],
    bool legacy_credentials_enabled) {
  if (private_key == NULL || app_id == NULL || key_handle == NULL ||
      generation == NULL)
    return false;

  uint8_t expected[SHA256_DIGEST_LENGTH];
  key_handle_hmac(private_key, app_id, key_handle, generation, true, expected);
  bool valid =
      memcmp_s(key_handle + KEY_PATH_LEN, expected, sizeof(expected)) == 0;
  if (!valid && legacy_credentials_enabled) {
    key_handle_hmac(private_key, app_id, key_handle, generation, false,
                    expected);
    valid =
        memcmp_s(key_handle + KEY_PATH_LEN, expected, sizeof(expected)) == 0;
  }
  memzero(expected, sizeof(expected));
  return valid;
}

static const HDNode* generateKeyHandle(const uint8_t app_id[],
                                       uint8_t key_handle[]) {
  // Derivation path is m/U2F'/r'/r'/r'/r'/r'/r'/r'/r'
  //
  // The path is not secret: it is the first half of the key handle, which the
  // relying party stores. The key's secrecy rests on the U2F root. The path
  // still draws through the RNG gate rather than random32(): a stuck or weak
  // generator would repeat paths and give unrelated sites the same public key,
  // linking the user across them. Registration fails rather than minting a
  // credential on an untrusted generator.
  uint32_t key_path[KEY_PATH_ENTRIES];
  if (!random_buffer_checked((uint8_t*)key_path, sizeof(key_path))) {
    debugLog(0, "", "ERR: RNG self-test failed");
    memzero(key_handle, KEY_HANDLE_LEN);
    return NULL;
  }
  for (uint32_t i = 0; i < KEY_PATH_ENTRIES; i++) {
    key_path[i] |= 0x80000000;  // high bit for hardened keys
  }

  // First half of keyhandle is key_path
  memcpy(key_handle, key_path, KEY_PATH_LEN);

  // prepare keypair from /random data
  const HDNode* node = getDerivedNode(key_path, KEY_PATH_ENTRIES);
  if (!node) {
    memzero(key_path, sizeof(key_path));
    memzero(key_handle, KEY_HANDLE_LEN);
    return NULL;
  }

  uint8_t generation[PASSKEY_CREDENTIAL_GENERATION_SIZE];
  bool legacy_credentials_enabled;
  if (!storage_getPasskeyCredentialGeneration(generation,
                                              &legacy_credentials_enabled)) {
    debugLog(0, "", "ERR: Credential generation unavailable");
    memzero(key_path, sizeof(key_path));
    memzero(key_handle, KEY_HANDLE_LEN);
    return NULL;
  }
  (void)legacy_credentials_enabled;

  // Bind the public key handle to the active authenticator-reset generation.
  key_handle_hmac(node->private_key, app_id, key_handle, generation, true,
                  &key_handle[KEY_PATH_LEN]);
  memzero(generation, sizeof(generation));
  memzero(key_path, sizeof(key_path));

  // Done!
  return node;
}

static const HDNode* validateKeyHandle(const uint8_t app_id[],
                                       const uint8_t key_handle[]) {
  uint32_t key_path[KEY_PATH_ENTRIES];
  memcpy(key_path, key_handle, KEY_PATH_LEN);
  for (unsigned int i = 0; i < KEY_PATH_ENTRIES; i++) {
    // check high bit for hardened keys
    if (!(key_path[i] & 0x80000000)) {
      return NULL;
    }
  }

  const HDNode* node = getDerivedNode(key_path, KEY_PATH_ENTRIES);
  if (!node) return NULL;

  uint8_t generation[PASSKEY_CREDENTIAL_GENERATION_SIZE];
  bool legacy_credentials_enabled;
  if (!storage_getPasskeyCredentialGeneration(generation,
                                              &legacy_credentials_enabled))
    return NULL;
  const bool valid = u2f_key_handle_authenticator_is_valid(
      node->private_key, app_id, key_handle, generation,
      legacy_credentials_enabled);
  memzero(generation, sizeof(generation));
  if (!valid) return NULL;

  // Done!
  return node;
}

bool u2f_generate_credential(const uint8_t app_id[32], uint8_t key_handle[64],
                             uint8_t private_key[32], uint8_t public_key[65]) {
  const HDNode* node = generateKeyHandle(app_id, key_handle);
  if (node == NULL) return false;
  memcpy(private_key, node->private_key, 32);
  ecdsa_get_public_key65(&nist256p1, node->private_key, public_key);
  return true;
}

bool u2f_load_credential(const uint8_t app_id[32], const uint8_t key_handle[64],
                         uint8_t private_key[32], uint8_t public_key[65]) {
  const HDNode* node = validateKeyHandle(app_id, key_handle);
  if (node == NULL) return false;
  memcpy(private_key, node->private_key, 32);
  ecdsa_get_public_key65(&nist256p1, node->private_key, public_key);
  return true;
}

/* rp_id == NULL is the authenticator reset, which is destructive. */
bool ctap2_request_user_presence(const char* rp_id, bool registration) {
  const char* title = !rp_id
                          ? "Reset Passkeys"
                          : (registration ? "Create Passkey" : "Use Passkey");
  bool fits =
      !rp_id ? layoutU2FDialog(true, title,
                               "Delete all passkeys, the passkey PIN and U2F "
                               "logins?")
             : layoutU2FDialog(
                   true, title,
                   registration ? "Create a passkey for %s?" : "Sign in to %s?",
                   rp_id);
  if (!fits) {
    // rp_id is host-controlled and can run up to 253 chars; the credential
    // is bound to the FULL string (see ctap2's sha256_Raw() over rp_id), so
    // an rp_id the user can't read in full must not be silently approved.
    layoutHome();
    return false;
  }
  bool saw_button_up = false;
  for (uint32_t remaining = 10 * U2F_TIMEOUT; remaining > 0; --remaining) {
    if (ctap_cancelled) {
      layoutHome();
      return false;
    }
    saw_button_up = saw_button_up || keepkey_button_up();
    if (saw_button_up && keepkey_button_down()) {
      layoutU2FDialog(false, title, "%s", rp_id ? rp_id : "Reset");
      return true;
    }
    if ((remaining % (U2F_TIMEOUT / 4)) == 0) {
      const uint8_t status = 0x02; /* CTAPHID_KEEPALIVE_STATUS_UPNEEDED */
      send_u2fhid_msg(U2FHID_KEEPALIVE, &status, 1);
    }
    usbPoll();
  }
  layoutHome();
  return false;
}

bool ctap2_user_presence_was_cancelled(void) { return ctap_cancelled; }

static void promptRegister(bool request, const U2F_REGISTER_REQ* req) {
#if 0
	// Users find it confusing when a Ledger and a KeepKey are plugged in
	// at the same time. To avoid that, we elect not to show a message in
	// this case.
	if (0 == memcmp(req->appId, BOGUS_APPID, U2F_APPID_SIZE)) {
		layoutU2FDialog(request, "U2f Register",
		                "Another U2F device was used to register in this application.");
	} else {
#else
  {
#endif
    const char* appname = "";
    bool readable = getReadableAppId(req->appId, &appname);
    layoutU2FDialog(
        request, "U2F Register",
        readable ? "Do you want to register with %s?"
                 : "Do you want to register with this U2F application?\n\n%s",
        appname);
  }
}

void u2f_register(const APDU* a) {
  static U2F_REGISTER_REQ last_req;
  const U2F_REGISTER_REQ* req = (U2F_REGISTER_REQ*)a->data;

  if (!storage_isInitialized()) {
    layout_warning_static("Cannot register u2f: not initialized");
    send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
    delay_ms(3000);
    return;
  }

  // Validate basic request parameters
  debugLog(0, "", "u2f register");
  if (APDU_LEN(*a) != sizeof(U2F_REGISTER_REQ)) {
    debugLog(0, "", "u2f register - badlen");
    send_u2f_error(U2F_SW_WRONG_LENGTH);
    return;
  }

  // If this request is different from last request, reset state machine
  if (memcmp(&last_req, req, sizeof(last_req)) != 0) {
    memcpy(&last_req, req, sizeof(last_req));
    last_req_state = INIT;
  }

  // First Time request, return not present and display request dialog
  if (last_req_state == INIT) {
    // error: testof-user-presence is required
    promptRegister(true, req);
    presence_step = 0;
    last_req_state = REG;
  }

  // Still awaiting Keypress
  if (last_req_state == REG) {
    // error: testof-user-presence is required
    send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
    dialog_timeout = U2F_TIMEOUT;
    return;
  }

  // Buttons said yes
  if (last_req_state == REG_PASS) {
    uint8_t data[sizeof(U2F_REGISTER_RESP) + 2];
    U2F_REGISTER_RESP* resp = (U2F_REGISTER_RESP*)&data;
    memzero(data, sizeof(data));

    resp->registerId = U2F_REGISTER_ID;
    resp->keyHandleLen = KEY_HANDLE_LEN;
    // Generate keypair for this appId
    const HDNode* node =
        generateKeyHandle(req->appId, (uint8_t*)&resp->keyHandleCertSig);

    if (!node) {
      debugLog(0, "", "getDerivedNode Fail");
      send_u2f_error(U2F_SW_WRONG_DATA);  // error:bad key handle
      return;
    }

    ecdsa_get_public_key65(node->curve->params, node->private_key,
                           (uint8_t*)&resp->pubKey);

    memcpy(resp->keyHandleCertSig + resp->keyHandleLen, U2F_ATT_CERT,
           sizeof(U2F_ATT_CERT));

    uint8_t sig[64];
    U2F_REGISTER_SIG_STR sig_base;
    sig_base.reserved = 0;
    memcpy(sig_base.appId, req->appId, U2F_APPID_SIZE);
    memcpy(sig_base.chal, req->chal, U2F_CHAL_SIZE);
    memcpy(sig_base.keyHandle, &resp->keyHandleCertSig, KEY_HANDLE_LEN);
    memcpy(sig_base.pubKey, &resp->pubKey, U2F_PUBKEY_LEN);
    if (ecdsa_sign(&nist256p1, HASHER_SHA2, U2F_ATT_PRIV_KEY,
                   (uint8_t*)&sig_base, sizeof(sig_base), sig, NULL,
                   NULL) != 0) {
      send_u2f_error(U2F_SW_WRONG_DATA);
      return;
    }

    // Where to write the signature in the response
    uint8_t* resp_sig =
        resp->keyHandleCertSig + resp->keyHandleLen + sizeof(U2F_ATT_CERT);
    // Convert to der for the response
    const uint8_t sig_len = ecdsa_sig_to_der(sig, resp_sig);

    // Append success bytes
    memcpy(resp->keyHandleCertSig + resp->keyHandleLen + sizeof(U2F_ATT_CERT) +
               sig_len,
           "\x90\x00", 2);

    int l = 1 /* registerId */ + U2F_PUBKEY_LEN + 1 /* keyhandleLen */ +
            resp->keyHandleLen + sizeof(U2F_ATT_CERT) + sig_len + 2;

    last_req_state = INIT;
    dialog_timeout = 0;
    send_u2f_msg(data, l);

    promptRegister(false, req);
    return;
  }

  // Didnt expect to get here
  dialog_timeout = 0;
}

static void promptAuthenticate(bool request, const U2F_AUTHENTICATE_REQ* req) {
  const char* appname = "";
  bool readable = getReadableAppId(req->appId, &appname);
  layoutU2FDialog(request, "U2F Authenticate",
                  readable ? "Log in to %s?" : "Do you want to log in?\n\n%s",
                  appname);
}

void u2f_authenticate(const APDU* a) {
  const U2F_AUTHENTICATE_REQ* req = (U2F_AUTHENTICATE_REQ*)a->data;
  static U2F_AUTHENTICATE_REQ last_req;

  if (!storage_isInitialized()) {
    layout_warning_static("Cannot authenticate u2f: not initialized");
    send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
    delay_ms(3000);
    return;
  }

  if (APDU_LEN(*a) < 64) {  /// FIXME: decent value
    debugLog(0, "", "u2f authenticate - badlen");
    send_u2f_error(U2F_SW_WRONG_LENGTH);
    return;
  }

  if (req->keyHandleLen != KEY_HANDLE_LEN) {
    debugLog(0, "", "u2f auth - bad keyhandle len");
    send_u2f_error(U2F_SW_WRONG_DATA);  // error:bad key handle
    return;
  }

  const HDNode* node = validateKeyHandle(req->appId, req->keyHandle);

  if (!node) {
    debugLog(0, "", "u2f auth - bad keyhandle len");
    send_u2f_error(U2F_SW_WRONG_DATA);  // error:bad key handle
    return;
  }

  if (a->p1 == U2F_AUTH_CHECK_ONLY) {
    debugLog(0, "", "u2f authenticate check");
    // This is a success for a good keyhandle
    // A failed check would have happened earlier
    // error: testof-user-presence is required
    send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
    return;
  }

  if (a->p1 != U2F_AUTH_ENFORCE) {
    debugLog(0, "", "u2f authenticate unknown");
    // error:bad key handle
    send_u2f_error(U2F_SW_WRONG_DATA);
    return;
  }

  debugLog(0, "", "u2f authenticate enforce");

  if (memcmp(&last_req, req, sizeof(last_req)) != 0) {
    memcpy(&last_req, req, sizeof(last_req));
    last_req_state = INIT;
  }

  if (last_req_state == INIT) {
    // error: testof-user-presence is required
    promptAuthenticate(true, req);
    presence_step = 0;
    last_req_state = AUTH;
  }

  // Awaiting Keypress
  if (last_req_state == AUTH) {
    // error: testof-user-presence is required
    send_u2f_error(U2F_SW_CONDITIONS_NOT_SATISFIED);
    dialog_timeout = U2F_TIMEOUT;
    return;
  }

  // Buttons said yes
  if (last_req_state == AUTH_PASS) {
    uint8_t buf[sizeof(U2F_AUTHENTICATE_RESP) + 2];
    U2F_AUTHENTICATE_RESP* resp = (U2F_AUTHENTICATE_RESP*)&buf;

    const uint32_t ctr = storage_nextU2FCounter();
    resp->flags = U2F_AUTH_FLAG_TUP;
    resp->ctr[0] = ctr >> 24 & 0xff;
    resp->ctr[1] = ctr >> 16 & 0xff;
    resp->ctr[2] = ctr >> 8 & 0xff;
    resp->ctr[3] = ctr & 0xff;

    // Build and sign response
    U2F_AUTHENTICATE_SIG_STR sig_base;
    uint8_t sig[64];
    memcpy(sig_base.appId, req->appId, U2F_APPID_SIZE);
    sig_base.flags = resp->flags;
    memcpy(sig_base.ctr, resp->ctr, 4);
    memcpy(sig_base.chal, req->chal, U2F_CHAL_SIZE);
    if (ecdsa_sign(&nist256p1, HASHER_SHA2, node->private_key,
                   (uint8_t*)&sig_base, sizeof(sig_base), sig, NULL,
                   NULL) != 0) {
      send_u2f_error(U2F_SW_WRONG_DATA);
      return;
    }

    // Copy DER encoded signature into response
    const uint8_t sig_len = ecdsa_sig_to_der(sig, resp->sig);

    // Append OK
    memcpy(buf + sizeof(U2F_AUTHENTICATE_RESP) - U2F_MAX_EC_SIG_SIZE + sig_len,
           "\x90\x00", 2);
    last_req_state = INIT;
    dialog_timeout = 0;
    send_u2f_msg(
        buf, sizeof(U2F_AUTHENTICATE_RESP) - U2F_MAX_EC_SIG_SIZE + sig_len + 2);

    promptAuthenticate(false, req);
  }
}

void send_u2f_error(const uint16_t err) {
  uint8_t data[2];
  data[0] = err >> 8 & 0xFF;
  data[1] = err & 0xFF;
  send_u2f_msg(data, 2);
}

void send_u2f_msg(const uint8_t* data, const uint32_t len) {
  send_u2fhid_msg(U2FHID_MSG, data, len);
}

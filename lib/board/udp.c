/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (C) 2017 Saleem Rashid <trezor@saleemrashid.com>
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

#ifdef EMULATOR

#include "keepkey/board/usb.h"
#include "keepkey/board/timer.h"
#include "keepkey/emulator/emulator.h"
#include "keepkey/firmware/rust.h"

#include <stdint.h>
#include <assert.h>

void usbInit(const char *origin_url) {
  (void)origin_url;
  emulatorSocketInit();
}

void usbPoll(void) {
  static uint8_t buf[64] __attribute__((aligned(4)));
  size_t len;

  int iface = 0;
  if (0 < (len = emulatorSocketRead(&iface, buf, sizeof(buf)))) {
    if (!tiny) {
      if (iface == 0) {
        rust_usb_rx_callback(ENDPOINT_ADDRESS_MAIN_OUT, &buf, len);
      } else if (iface == 1) {
#if DEBUG_LINK
        rust_usb_rx_callback(ENDPOINT_ADDRESS_DEBUG_OUT, &buf, len);
#else
        rust_usb_rx_callback(ENDPOINT_ADDRESS_MAIN_OUT, &buf, len);
#endif
      }
    } else {
      assert(false && "not yet implemented");
      // msg_read_tiny(msg.message, sizeof(msg.message));
    }
  }
}

bool usb_tx(uint8_t *msg, uint32_t len) {
  return emulatorSocketWrite(0, msg, len);
}

#if DEBUG_LINK
bool usb_debug_tx(uint8_t *msg, uint32_t len) {
  return emulatorSocketWrite(1, msg, len);
}
#endif

#endif

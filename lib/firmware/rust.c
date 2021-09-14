/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2021 Reid Rankin <reidrankin@gmail.com>
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

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "keepkey/firmware/rust.h"

void rust_init(void) {}

void rust_exec(void) {}

void rust_usb_rx_callback(uint8_t ep, uint8_t* buf, size_t len) {
  (void)ep;
  (void)buf;
  (void)len;
}

void rust_get_label(char* buf, size_t len) {
  (void)buf;
  (void)len;
}

void rust_button_handler(bool pressed) {
  (void)pressed;
}

void rust_layout_warning_static(LayoutWarningStaticType type) {
  (void)type;
}

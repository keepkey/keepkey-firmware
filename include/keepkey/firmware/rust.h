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

#ifndef RUST_H
#define RUST_H

#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/keepkey_leds.h"

#include <stdint.h>
#include <stdlib.h>

extern void rust_init(void);
extern void rust_exec(void);
extern void rust_usb_rx_callback(uint8_t ep, uint8_t* buf, size_t len);
extern void rust_get_label(char* buf, size_t len);
extern void rust_button_handler(bool pressed);
extern void rust_layout_warning_static(LayoutWarningStaticType type);

// void shutdown(void);
// void board_reset(void);

// uint32_t fi_defense_delay(volatile uint32_t value);
// void delay_us(uint32_t us);
// void delay_ms(uint32_t ms);
// uint64_t get_clock_ms(void);

// const char* get_scm_revision(void);
// void desig_get_unique_id(uint32_t result[3]);

// bool is_mfg_mode(void);
// bool set_mfg_mode_off(void);

// const char* flash_getModel(void);
// bool flash_setModel(const char* buf, size_t len);

// // For hashing bootloader, etc.
// const uint8_t* flash_write_helper(Allocation group, size_t* pLen, size_t skip);

// bool storage_read(uint8_t* buf, size_t len);
// void storage_wipe(void);
// bool storage_write(const uint8_t* buf, size_t len);

// bool keepkey_button_down(void);

// Canvas* display_canvas(void);

// void led_func(LedAction act);

// bool usb_tx(uint8_t *msg, uint32_t len);
// #if DEBUG_LINK
// bool usb_debug_tx(uint8_t *message, uint32_t len);
// #endif
// void usbReconnect(void);

#endif // RUST_H

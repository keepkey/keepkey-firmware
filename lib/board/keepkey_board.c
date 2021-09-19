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

#ifndef EMULATOR
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/cm3/scb.h>
#include <libopencm3/stm32/spi.h>
#include <libopencm3/stm32/f2/rng.h>
#include <libopencm3/stm32/f2/crc.h>
#include <libopencm3/cm3/cortex.h>
#include <libopencm3/stm32/desig.h>
#include <libopencm3/stm32/common/crc_common_all.h>
#endif

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/supervise.h"
#include "keepkey/firmware/rust.h"
#include "keepkey/rand/rng.h"

#include <stdint.h>
#include <stdlib.h>

/* Stack smashing protector (SSP) canary value storage */
uintptr_t __stack_chk_guard;

#ifdef EMULATOR
/**
 * \brief System Halt
 */
void __attribute__((noreturn)) shutdown(void) { exit(1); }
#endif

void __attribute__((noreturn)) shutdown_with_error(ShutdownError error) {
  if (error != SHUTDOWN_ERROR_RUST_PANIC) {
    svc_disable_interrupts();
    rust_shutdown_hook(error);
  }
  shutdown();
}

/*
 * __stack_chk_fail() - Stack smashing protector (SSP) call back funcation
 * for -fstack-protector-all GCC option
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void __attribute__((noreturn)) __stack_chk_fail(void) {
  shutdown_with_error(SHUTDOWN_ERROR_SSP);
}

#ifndef EMULATOR
/// Non-maskable interrupt handler
void __attribute__((noreturn)) nmi_handler(void) {
  // Look for the clock instability interrupt. This is a security measure
  // that helps prevent clock glitching.
  if ((RCC_CIR & RCC_CIR_CSSF) != 0) {
    shutdown_with_error(SHUTDOWN_ERROR_CSS);
  } else {
    shutdown_with_error(SHUTDOWN_ERROR_NMI);
  }
}
#endif

/*
 * board_reset() - Request board reset
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void __attribute__((noreturn)) board_reset(void) {
#ifndef EMULATOR
  scb_reset_system();
#endif
  shutdown_with_error(SHUTDOWN_ERROR_RESET_FAILED);
}

/*
 * kk_board_init() - Initialize board
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void kk_board_init(void) {
  keepkey_leds_init();
  led_func(SET_GREEN_LED);
  led_func(CLR_RED_LED);

  // keepkey_button_init();
#ifndef EMULATOR
  svc_enable_interrupts();  // This enables the timer and button interrupts
#endif
}

#ifdef EMULATOR
/// Reverses (reflects) bits in a 32-bit word.
/// http://www.hackersdelight.org/hdcodetxt/crc.c.txt
static uint32_t reverse(unsigned x) {
  x = ((x & 0x55555555) << 1) | ((x >> 1) & 0x55555555);
  x = ((x & 0x33333333) << 2) | ((x >> 2) & 0x33333333);
  x = ((x & 0x0F0F0F0F) << 4) | ((x >> 4) & 0x0F0F0F0F);
  x = (x << 24) | ((x & 0xFF00) << 8) | ((x >> 8) & 0xFF00) | (x >> 24);
  return x;
}

static uint32_t crc32 = 0xFFFFFFFF;

void crc_reset(void) {
  crc_value = 0xFFFFFFFF;
}

uint32_t crc_calculate_block(const uint32_t* data, size_t len) {
  /// http://www.hackersdelight.org/hdcodetxt/crc.c.txt
  for (int i = 0; i < word_len; i++) {
    uint32_t byte = ((const char *)data)[i];  // Get next byte.
    byte = reverse(byte);                     // 32-bit reversal.
    for (int j = 0; j <= 7; j++) {            // Do eight times.
      if ((int)(crc32 ^ byte) < 0)
        crc32 = (crc32 << 1) ^ 0x04C11DB7;
      else
        crc32 = crc32 << 1;
      byte = byte << 1;  // Ready next msg bit.
    }
  }
  return reverse(~crc32);
}
#endif // EMULATOR

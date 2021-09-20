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

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/cm3/scb.h>
#include <libopencm3/stm32/spi.h>
#include <libopencm3/stm32/f2/rng.h>
#include <libopencm3/stm32/f2/crc.h>
#include <libopencm3/cm3/cortex.h>
#include <libopencm3/stm32/desig.h>
#include <libopencm3/stm32/common/crc_common_all.h>

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/supervise.h"
#include "keepkey/firmware/rust.h"
#include "keepkey/rand/rng.h"

#include <stdint.h>
#include <stdlib.h>

/* Stack smashing protector (SSP) canary value storage */
uintptr_t __stack_chk_guard;

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

/*
 * board_reset() - Request board reset
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void __attribute__((noreturn)) board_reset(void) {
  scb_reset_system();
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

  gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, (GPIO11 | GPIO12));
  gpio_set_af(GPIOA, GPIO_AF10, (GPIO11 | GPIO12));

  // keepkey_button_init();
  svc_enable_interrupts();  // This enables the timer and button interrupts
}

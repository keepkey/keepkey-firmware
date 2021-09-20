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
#include <libopencm3/stm32/exti.h>
#include <libopencm3/stm32/f2/nvic.h>
#include <libopencm3/stm32/syscfg.h>

#include "keepkey/board/keepkey_button.h"
#include "keepkey/board/keepkey_leds.h"
#include "keepkey/board/supervise.h"
#include "keepkey/firmware/rust.h"

#include <stddef.h>

static const uint16_t BUTTON_PIN = GPIO7;
static const uint32_t BUTTON_PORT = GPIOB;
static const uint32_t BUTTON_EXTI = EXTI7;

/*
 * keepkey_button_init() - Initialize push button interrupt registers
 * and variables
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void keepkey_button_init(void) {
  gpio_mode_setup(BUTTON_PORT, GPIO_MODE_INPUT, GPIO_PUPD_NONE, BUTTON_PIN);

  /* Configure the EXTI subsystem. */
  exti_select_source(BUTTON_EXTI, GPIOB);
  exti_set_trigger(BUTTON_EXTI, EXTI_TRIGGER_BOTH);
  exti_enable_request(BUTTON_EXTI);
}

/*
 * keepkey_button_up() - Get push button in up state
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false state of push button up
 */
bool keepkey_button_up(void) {
  uint16_t port = gpio_port_read(BUTTON_PORT);
  return port & BUTTON_PIN;
}

/*
 * keepkey_button_down() - Get push button in down state
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false state of push button down
 */
bool keepkey_button_down(void) { return !keepkey_button_up(); }

void buttonisr_usr(void) {
  static bool last_pressed_state = false;
  static bool last_pressed_state_initialized = false;

  bool pressed_state = keepkey_button_down();
  if (!last_pressed_state_initialized || pressed_state != last_pressed_state) {
    last_pressed_state = pressed_state;
    rust_button_handler(pressed_state);
  }

  svc_busr_return();  // this MUST be called last to properly clean up and return
}

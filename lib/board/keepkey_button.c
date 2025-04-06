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
#include <libopencm3/stm32/exti.h>
#ifdef DEV_DEBUG
#include <libopencm3/stm32/f4/nvic.h>
#else
#include <libopencm3/stm32/f2/nvic.h>
#endif
#include <libopencm3/stm32/syscfg.h>
#endif

#include "keepkey/board/keepkey_button.h"
#include "keepkey/board/keepkey_leds.h"
#include "keepkey/board/supervise.h"

#include <stddef.h>

static Handler on_press_handler = NULL;
static Handler on_release_handler = NULL;

static void *on_release_handler_context = NULL;
static void *on_press_handler_context = NULL;

#ifndef EMULATOR
static const uint32_t BUTTON_PORT = GPIOB;
#ifdef  DEV_DEBUG
static const uint16_t BUTTON_PIN = GPIO9;
static const uint32_t BUTTON_EXTI = EXTI9;
#else
static const uint16_t BUTTON_PIN = GPIO7;
static const uint32_t BUTTON_EXTI = EXTI7;
#endif  // DEV_DEBUG
#endif // EMULATOR

void kk_keepkey_button_init(void) {
  on_press_handler = NULL;
  on_press_handler_context = NULL;

  on_release_handler = NULL;
  on_release_handler_context = NULL;
}

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
  on_press_handler = NULL;
  on_press_handler_context = NULL;

  on_release_handler = NULL;
  on_release_handler_context = NULL;

#ifndef EMULATOR
  gpio_mode_setup(BUTTON_PORT, GPIO_MODE_INPUT, GPIO_PUPD_NONE, BUTTON_PIN);
  /* Set up port B */

  /* Configure the EXTI subsystem. */
  exti_select_source(BUTTON_EXTI, GPIOB);

  exti_set_trigger(BUTTON_EXTI, EXTI_TRIGGER_BOTH);

  exti_enable_request(BUTTON_EXTI);

#endif
}

/*
 * keepkey_button_set_on_press_handler() - Set callback handler for
 * button pressed
 *
 * INPUT
 *     - handler: handler function
 *     - context: pointer to release handler state info.
 * OUTPUT
 *     none
 *
 */
void keepkey_button_set_on_press_handler(Handler handler, void *context) {
  on_press_handler = handler;
  on_press_handler_context = context;
}

/*
 * keepkey_button_set_on_release_handler() - Set handler for
 * button released
 *
 * INPUT
 *     - handler: handler function
 *     - context: pointer to release handler state info.
 * OUTPUT
 *     none
 *
 */
void keepkey_button_set_on_release_handler(Handler handler, void *context) {
  on_release_handler = handler;
  on_release_handler_context = context;
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
#ifndef EMULATOR
  uint16_t port = gpio_port_read(BUTTON_PORT);
  return port & BUTTON_PIN;
#else
  return false;
#endif
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
#ifndef EMULATOR
  uint16_t gpState = gpio_get(BUTTON_PORT, BUTTON_PIN) & BUTTON_PIN;

  if (gpState) {
    if (on_release_handler) {
      on_release_handler(on_release_handler_context);
    }
  } else {
    if (on_press_handler) {
      on_press_handler(on_press_handler_context);
    }
  }

  svc_busr_return();  // this MUST be called last to properly clean up and
                      // return

#endif
}

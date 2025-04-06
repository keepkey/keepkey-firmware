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

#include <stddef.h>

#include "keepkey/board/keepkey_leds.h"
#include "keepkey/board/pin.h"

#ifndef EMULATOR
#ifdef  DEV_DEBUG
static const Pin GREEN_LED = {GPIOC, GPIO1};
static const Pin RED_LED = {GPIOB, GPIO8};
#else
static const Pin GREEN_LED = {GPIOC, GPIO14};
static const Pin RED_LED = {GPIOB, GPIO8};
#endif  // DEV_DEBUG
#endif  // EMULATOR

/*
 * keepkey_leds_init() - Initialize gpios for LEDs
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void keepkey_leds_init(void) {
#ifndef EMULATOR
  pin_init_output(&GREEN_LED, PUSH_PULL_MODE, NO_PULL_MODE);
  // pin_init_output(&RED_LED, PUSH_PULL_MODE, NO_PULL_MODE);

  led_func(CLR_GREEN_LED);
  led_func(CLR_RED_LED);
#endif
}

/*
 * led_func() - Set LED states
 *
 * INPUT
 *     - act: led action
 * OUTPUT
 *     none
 */
void led_func(LedAction act) {
#ifndef EMULATOR
  switch (act) {
    case CLR_GREEN_LED:
      SET_PIN(GREEN_LED);
      break;

    case SET_GREEN_LED:
      CLEAR_PIN(GREEN_LED);
      break;

    case TGL_GREEN_LED:
      TOGGLE_PIN(GREEN_LED);
      break;

    case CLR_RED_LED:
      SET_PIN(RED_LED);
      break;

    case SET_RED_LED:
      CLEAR_PIN(RED_LED);
      break;

    case TGL_RED_LED:
      TOGGLE_PIN(RED_LED);
      break;

    default:
      /* No action */
      break;
  }
#endif
}

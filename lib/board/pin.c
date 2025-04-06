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
#endif

#include "keepkey/board/pin.h"

/*
 * pin_init_output() - Initialize GPIO for LED
 *
 * INPUT
 *     - pin: pointer pin assignment
 *     - output_mode: pin output state
 *     - pull_mode: input mode
 * OUTPUT
 *     none
 */
void pin_init_output(const Pin *pin, OutputMode output_mode,
                     PullMode pull_mode) {
#ifndef EMULATOR
  uint8_t output_mode_setpoint;
  uint8_t pull_mode_setpoint;

  switch (output_mode) {
    case OPEN_DRAIN_MODE:
      output_mode_setpoint = GPIO_OTYPE_OD;
      break;
    case PUSH_PULL_MODE:
    default:
      output_mode_setpoint = GPIO_OTYPE_PP;
      break;
  }

  switch (pull_mode) {
    case PULL_UP_MODE:
      pull_mode_setpoint = GPIO_PUPD_PULLUP;
      break;
    case PULL_DOWN_MODE:
      pull_mode_setpoint = GPIO_PUPD_PULLDOWN;
      break;

    case NO_PULL_MODE:
    default:
      pull_mode_setpoint = GPIO_PUPD_NONE;
      break;
  }

  /* Set pin parameters */
  gpio_mode_setup(pin->port, GPIO_MODE_OUTPUT, pull_mode_setpoint, pin->pin);
  gpio_set_output_options(pin->port, output_mode_setpoint, GPIO_OSPEED_100MHZ,
                          pin->pin);
#endif
}

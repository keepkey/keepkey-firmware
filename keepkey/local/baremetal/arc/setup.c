/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/spi.h>
#include <libopencm3/stm32/f2/rng.h>

#include "firmware/keepkey_led.h"

void setup(void)
{
	// setup clock
	clock_scale_t clock = hse_8mhz_3v3[CLOCK_3V3_120MHZ];
	rcc_clock_setup_hse_3v3(&clock);

	// enable GPIO clock - A (oled), B(oled), C (buttons)
	rcc_peripheral_enable_clock(&RCC_AHB1ENR, 
                RCC_AHB1ENR_IOPAEN | // GPIO A Enable
                RCC_AHB1ENR_IOPBEN | // GPIO B Enable
                RCC_AHB1ENR_IOPCEN); // GPIO C Enable

        led_init();

	// enable OTG FS clock
	rcc_peripheral_enable_clock(&RCC_AHB2ENR, RCC_AHB2ENR_OTGFSEN);

	// enable RNG
	rcc_peripheral_enable_clock(&RCC_AHB2ENR, RCC_AHB2ENR_RNGEN);
	RNG_CR |= RNG_CR_IE | RNG_CR_RNGEN;

	// set GPIO for buttons
	//gpio_mode_setup(GPIOB, GPIO_MODE_INPUT, GPIO_PUPD_PULLUP, GPIO7);

	// enable OTG_FS
	gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO9 | GPIO11 | GPIO12);
	gpio_set_af(GPIOA, GPIO_AF10, GPIO9 | GPIO11 | GPIO12);
}

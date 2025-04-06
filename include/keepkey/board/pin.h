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

#ifndef PIN_H
#define PIN_H

#ifndef EMULATOR
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#endif

#include <inttypes.h>

#define SET_PIN(p) GPIO_BSRR((p).port) = (p).pin
#define CLEAR_PIN(p) GPIO_BSRR((p).port) = ((p).pin << 16)
#define TOGGLE_PIN(p) GPIO_ODR((p).port) ^= (p).pin

typedef enum {
  PUSH_PULL_MODE,
  OPEN_DRAIN_MODE,

  NUM_PIN_MODES
} OutputMode;

typedef enum {
  PULL_UP_MODE,
  PULL_DOWN_MODE,
  NO_PULL_MODE,

  NUM_PULL_MODES
} PullMode;

typedef struct {
  uint32_t port;
  uint16_t pin;
} Pin;

#ifndef EMULATOR

static const Pin nDC_PIN = {GPIOC, GPIO2};
static const Pin nSEL_PIN = {GPIOC, GPIO5};
static const Pin nRESET_PIN = {GPIOC, GPIO3};

#ifndef DEV_DEBUG
// display signals for standard keepkey
static const Pin nOE_PIN = {GPIOA, GPIO8};
static const Pin nWE_PIN = {GPIOA, GPIO9};
static const Pin BACKLIGHT_PWR_PIN = {GPIOB, GPIO0};
#endif
#endif  // EMULATOR


#ifdef DEV_DEBUG
static const Pin SCOPE_PIN = {GPIOC, GPIO7};
#endif


void pin_init_output(const Pin *pin, OutputMode output_mode,
                     PullMode pull_mode);

#endif

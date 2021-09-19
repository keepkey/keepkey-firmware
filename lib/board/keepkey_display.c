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

#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/pin.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/supervise.h"
#include "keepkey/firmware/rust.h"

#include <string.h>

#pragma GCC push_options
#pragma GCC optimize("-O3")

#ifndef EMULATOR
static const Pin nOE_PIN = {GPIOA, GPIO8};
static const Pin nWE_PIN = {GPIOA, GPIO9};
static const Pin nDC_PIN = {GPIOB, GPIO1};

static const Pin nSEL_PIN = {GPIOA, GPIO10};
static const Pin nRESET_PIN = {GPIOB, GPIO5};

static const Pin BACKLIGHT_PWR_PIN = {GPIOB, GPIO0};
#endif

/*
 * display_write_reg() - Write data to display register
 *
 * INPUT
 *     - reg: display register value
 * OUTPUT
 *     none
 */
static void display_write_reg(uint8_t reg) {
#ifndef EMULATOR

  svc_disable_interrupts();

  /* Set up the data */
  GPIO_BSRR(GPIOA) = 0x000000FF & (uint32_t)reg;

  /* Set nOLED_SEL low, nMEM_OE high, and nMEM_WE high. */
  CLEAR_PIN(nSEL_PIN);
  SET_PIN(nOE_PIN);
  SET_PIN(nWE_PIN);

  __asm__("nop");
  __asm__("nop");

  /* Set nDC low */
  CLEAR_PIN(nDC_PIN);

  __asm__("nop");
  __asm__("nop");
  __asm__("nop");
  __asm__("nop");

  /* Set nMEM_WE low */
  CLEAR_PIN(nWE_PIN);

  __asm__("nop");
  __asm__("nop");
  __asm__("nop");
  __asm__("nop");
  __asm__("nop");

  /* Set nMEM_WE high */
  SET_PIN(nWE_PIN);

  __asm__("nop");
  __asm__("nop");

  /* Set nOLED_SEL high */
  SET_PIN(nSEL_PIN);
  GPIO_BSRR(GPIOA) = 0x00FF0000;

  __asm__("nop");
  __asm__("nop");
  __asm__("nop");
  __asm__("nop");

  svc_enable_interrupts();

#endif
}

/*
 * display_reset() - Reset display io port
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
static void display_reset(void) {
#ifndef EMULATOR
  CLEAR_PIN(nRESET_PIN);

  delay_ms(10);

  SET_PIN(nRESET_PIN);

  delay_ms(50);
#endif
}

/*
 * display_reset_io() - reset display io port
 *
 * INPUT -  none
 * OUTPUT -  none
 */
static void display_reset_io(void) {
#ifndef EMULATOR
  svc_disable_interrupts();
  SET_PIN(nRESET_PIN);
  CLEAR_PIN(BACKLIGHT_PWR_PIN);
  SET_PIN(nWE_PIN);
  SET_PIN(nOE_PIN);
  SET_PIN(nDC_PIN);
  SET_PIN(nSEL_PIN);

  GPIO_BSRR(GPIOA) = 0x00FF0000;
  svc_enable_interrupts();
#endif
}

/*
 * display_configure_io() - Setup display io port
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
static void display_configure_io(void) {
#ifndef EMULATOR
  /* Set up port A */
  gpio_mode_setup(GPIOA, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE,
                  GPIO0 | GPIO1 | GPIO2 | GPIO3 | GPIO4 | GPIO5 | GPIO6 |
                      GPIO7 | GPIO8 | GPIO9 | GPIO10);

  gpio_set_output_options(GPIOA, GPIO_OTYPE_PP, GPIO_OSPEED_100MHZ,
                          GPIO0 | GPIO1 | GPIO2 | GPIO3 | GPIO4 | GPIO5 |
                              GPIO6 | GPIO7 | GPIO8 | GPIO9 | GPIO10);

  /* Set up port B */
  gpio_mode_setup(GPIOB, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE,
                  GPIO0 | GPIO1 | GPIO5);

  gpio_set_output_options(GPIOB, GPIO_OTYPE_PP, GPIO_OSPEED_100MHZ,
                          GPIO0 | GPIO1 | GPIO5);

  /* Set to defaults */
  display_reset_io();
#endif
}

/*
 * display_prepare_gram_write() - Prepare display for write
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
static void display_prepare_gram_write(void) {
#ifndef EMULATOR
  display_write_reg((uint8_t)0x5C);
#endif
}

/*
 * display_write_ram() - Write data to display
 *
 * INPUT
 *     - val: display ram value
 * OUTPUT
 *     none
 */
static void display_write_ram(uint8_t val) {
#ifndef EMULATOR
  svc_disable_interrupts();

  /* Set up the data */
  GPIO_BSRR(GPIOA) = 0x000000FF & (uint32_t)val;

  /* Set nOLED_SEL low, nMEM_OE high, and nMEM_WE high. */
  CLEAR_PIN(nSEL_PIN);
  SET_PIN(nOE_PIN);
  SET_PIN(nWE_PIN);

  __asm__("nop");
  __asm__("nop");

  /* Set nDC high */
  SET_PIN(nDC_PIN);

  __asm__("nop");
  __asm__("nop");
  __asm__("nop");
  __asm__("nop");

  /* Set nMEM_WE low */
  CLEAR_PIN(nWE_PIN);

  __asm__("nop");
  __asm__("nop");
  __asm__("nop");
  __asm__("nop");
  __asm__("nop");

  /* Set nMEM_WE high */
  SET_PIN(nWE_PIN);

  __asm__("nop");
  __asm__("nop");

  /* Set nOLED_SEL high */
  SET_PIN(nSEL_PIN);
  GPIO_BSRR(GPIOA) = 0x00FF0000;

  __asm__("nop");
  __asm__("nop");
  __asm__("nop");
  __asm__("nop");

  svc_enable_interrupts();

#endif
}

/*
 * display_turn_on() - Turn on display
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void display_turn_on(void) { display_write_reg((uint8_t)0xAF); }

/*
 * display_turn_off() - Turn off display
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void display_turn_off(void) {
    display_write_reg((uint8_t)0xAE);
}


/*
 * display_set_brightness() - Set display brightness in percentage
 *
 * INPUT
 *     - percentage: brightness percentage
 * OUTPUT
 *     none
 */
void display_set_brightness(int percentage) {
#ifndef EMULATOR
  int v = percentage;

  /* Clip to be 0 <= value <= 100 */
  v = (v >= 0) ? v : 0;
  v = (v > 100) ? 100 : v;

  v = (0xFF * v) / 100;

  uint8_t reg_value = (uint8_t)v;

  display_write_reg((uint8_t)0xC1);
  display_write_ram(reg_value);
#endif
}

/*
 * display_refresh() - Refresh display
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void display_refresh(Canvas* canvas) {
  // bool didSomething = false;
  if (canvas->powered_dirty) {
    if (canvas->powered) {
      display_turn_on();
    } else {
      display_turn_off();
    }
    canvas->powered_dirty = false;
    // didSomething = true;
  }

  if (canvas->brightness_dirty) {
    display_set_brightness(canvas->brightness);
    canvas->brightness_dirty = false;
    // didSomething = true;
  }

  if (canvas->buffer_dirty) {
    display_prepare_gram_write();

    size_t half_width = canvas->width / 2;
#ifdef INVERT_DISPLAY
    for (size_t i = 0, j = canvas->width * canvas->height; j > 0; i += 2, j -= 2) {
#else
    for (size_t i = 0, j = 0; j < canvas->width * canvas->height; i += 2, j += 2) {
#endif
      if (i >= canvas->width) i -= canvas->width;
      size_t k = j;
      if (canvas->constant_power && i < half_width) k += half_width;
      uint8_t p1 = canvas->buffer[k];
#ifdef INVERT_DISPLAY
      uint8_t p2 = canvas->buffer[k - 1];
#else
      uint8_t p2 = canvas->buffer[k + 1];
#endif
      if (canvas->constant_power && i < half_width) {
        p1 = 0xFF - p1;
        p2 = 0xFF - p2;
      }
      uint8_t v = (0xF0 & p1) | (p2 >> 4);

      display_write_ram(v);
    }

    canvas->buffer_dirty = false;
    // didSomething = true;
  }

  // if (didSomething) {
    // led_func(TGL_RED_LED);
  // }
}

/*
 * display_hw_init(void)  - Display hardware initialization
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void display_hw_init(void) {
#ifndef EMULATOR
  display_configure_io();

  CLEAR_PIN(BACKLIGHT_PWR_PIN);

  display_reset();

  display_write_reg((uint8_t)0xFD);
  display_write_ram((uint8_t)0x12);

  display_turn_off();

  /* Divide DIVSET by 2 */
  display_write_reg((uint8_t)0xB3);
  display_write_ram((uint8_t)0x91);

  display_write_reg((uint8_t)0xCA);
  display_write_ram((uint8_t)0x3F);

  display_write_reg((uint8_t)0xA2);
  display_write_ram((uint8_t)0x00);

  display_write_reg((uint8_t)0xA1);
  display_write_ram((uint8_t)0x00);

  uint8_t row_start = START_ROW;
  uint8_t row_end = row_start + 64 - 1;

  /* Width is in units of 4 pixels/column (2 bytes at 4 bits/pixel) */
  int width = (256 / 4);
  uint8_t col_start = START_COL;
  uint8_t col_end = col_start + width - 1;

  display_write_reg((uint8_t)0x75);
  display_write_ram(row_start);
  display_write_ram(row_end);
  display_write_reg((uint8_t)0x15);
  display_write_ram(col_start);
  display_write_ram(col_end);

  /* Horizontal address increment */
  /* Disable colum address re-map */
  /* Disable nibble re-map */
  /* Scan from COM0 to COM[n-1] */
  /* Disable dual COM mode */
  display_write_reg((uint8_t)0xA0);
  display_write_ram((uint8_t)0x14);
  display_write_ram((uint8_t)0x11);

  /* GPIO0: pin HiZ, Input disabled */
  /* GPIO1: pin HiZ, Input disabled */
  display_write_reg((uint8_t)0xB5);
  display_write_ram((uint8_t)0x00);

  /* Enable internal Vdd regulator */
  display_write_reg((uint8_t)0xAB);
  display_write_ram((uint8_t)0x01);

  display_write_reg((uint8_t)0xB4);
  display_write_ram((uint8_t)0xA0);
  display_write_ram((uint8_t)0xFD);

  display_set_brightness(DEFAULT_DISPLAY_BRIGHTNESS);

  display_write_reg((uint8_t)0xC7);
  display_write_ram((uint8_t)0x0F);

  display_write_reg((uint8_t)0xB9);

  display_write_reg((uint8_t)0xB1);
  display_write_ram((uint8_t)0xE2);

  display_write_reg((uint8_t)0xD1);
  display_write_ram((uint8_t)0x82);
  display_write_ram((uint8_t)0x20);

  display_write_reg((uint8_t)0xBB);
  display_write_ram((uint8_t)0x1F);

  display_write_reg((uint8_t)0xB6);
  display_write_ram((uint8_t)0x08);

  display_write_reg((uint8_t)0xBE);
  display_write_ram((uint8_t)0x07);

  display_write_reg((uint8_t)0xA6);

  delay_ms(10);

  /* Set the screen to display-writing mode */
  display_prepare_gram_write();

  delay_ms(10);

  /* Make the display blank */
  int end = 64 * 256;
  int i;

  for (i = 0; i < end; i += 2) {
    display_write_ram((uint8_t)0x00);
  }

  /* Turn on 12V */
  SET_PIN(BACKLIGHT_PWR_PIN);

  delay_ms(100);

  display_turn_on();
#endif
}

uint8_t* get_static_canvas_buf(size_t len) {
  static uint8_t canvas_buf[KEEPKEY_DISPLAY_HEIGHT * KEEPKEY_DISPLAY_WIDTH] = { 0 };
  if (len > sizeof(canvas_buf)) return NULL;
  return canvas_buf;
}

size_t get_display_height(void) { return KEEPKEY_DISPLAY_HEIGHT; }

size_t get_display_width(void) { return KEEPKEY_DISPLAY_WIDTH; }

#pragma GCC pop_options

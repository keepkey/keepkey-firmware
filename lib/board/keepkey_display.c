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

#pragma GCC push_options
#pragma GCC optimize("-O3")

static uint8_t canvas_buffer[KEEPKEY_DISPLAY_HEIGHT * KEEPKEY_DISPLAY_WIDTH];
static Canvas canvas;
bool constant_power = false;

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
 * display_canvas_init() - Display canvas initialization
 *
 * INPUT
 *     none
 * OUTPUT
 *     pointer to canvas
 */
Canvas *display_canvas_init(void) {
  /* Prepare the canvas */
  canvas.buffer = canvas_buffer;
  canvas.width = KEEPKEY_DISPLAY_WIDTH;
  canvas.height = KEEPKEY_DISPLAY_HEIGHT;
  canvas.dirty = false;

  return &canvas;
}

/*
 * display_canvas() - Get pointer canvas
 *
 * INPUT
 *     none
 * OUTPUT
 *     pointer to canvas
 */
Canvas *display_canvas(void) { return &canvas; }

void (*DumpDisplay)(const uint8_t *buf) = 0;
void display_set_dump_callback(DumpDisplayCallback d) { DumpDisplay = d; }

/*
 * display_refresh() - Refresh display
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void display_refresh(void)
{
    if (DumpDisplay) {
        DumpDisplay(canvas.buffer);
    }

    if(!canvas.dirty)
    {
        return;
    }

    if (constant_power) {
        for (int y = 0; y < 64; y++) {
            for (int x = 0; x < 128; x++) {
                canvas.buffer[y * 256 + x] = 255 - canvas.buffer[y * 256 + x + 128];
            }
        }
    }

    display_prepare_gram_write();

    int num_writes = canvas.width * canvas.height;

    int i;
#ifdef INVERT_DISPLAY

  for (i = num_writes; i > 0; i -= 2) {
    uint8_t v = (0xF0 & canvas.buffer[i]) | (canvas.buffer[i - 1] >> 4);
#else

  for (i = 0; i < num_writes; i += 2) {
    uint8_t v = (0xF0 & canvas.buffer[i]) | (canvas.buffer[i + 1] >> 4);
#endif
    display_write_ram(v);
  }

  canvas.dirty = false;
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
void display_turn_off(void)
{
    display_write_reg((uint8_t)0xAE);
}

void display_constant_power(bool enabled)
{
    constant_power = enabled;
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

#pragma GCC pop_options

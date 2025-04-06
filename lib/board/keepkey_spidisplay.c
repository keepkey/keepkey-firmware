/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2025 markrypt0
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
#include <libopencm3/stm32/spi.h>
#endif

#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/pin.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/supervise.h"
#include "keepkey/board/keepkey_leds.h"

#pragma GCC push_options
#pragma GCC optimize("-O3")


static uint8_t canvas_buffer[KEEPKEY_DISPLAY_HEIGHT * KEEPKEY_DISPLAY_WIDTH];
static Canvas canvas;
bool constant_power = false;

static void spi_setup(void) {
  #ifndef EMULATOR

  gpio_set_output_options(GPIOA, GPIO_OTYPE_PP, GPIO_OSPEED_100MHZ,
    GPIO4 | GPIO5 | GPIO7);

  // enable SPI 1 for OLED display
  gpio_mode_setup(GPIOA, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO4 | GPIO5 | GPIO7);

  gpio_set_af(GPIOA, GPIO_AF5, GPIO4 | GPIO5 | GPIO7);


  // enable SPI clock
  rcc_periph_clock_enable(RCC_SPI1);
   
/*
int spi_init_master	(	
uint32_t 	spi,
uint32_t 	br,
uint32_t 	cpol,
uint32_t 	cpha,
uint32_t 	dff,
uint32_t 	lsbfirst 
)		

Parameters
[in]	spi	Unsigned int32. SPI peripheral identifier SPI Register base address.
[in]	br	Unsigned int32. Baudrate SPI peripheral baud rates.
[in]	cpol	Unsigned int32. Clock polarity SPI clock polarity.
[in]	cpha	Unsigned int32. Clock Phase SPI clock phase.
[in]	dff	Unsigned int32. Data frame format 8/16 bits SPI data frame format.
[in]	lsbfirst	Unsigned int32. Frame format lsb/msb first SPI lsb/msb first.

*/
  spi_init_master(
    SPI1, 
    SPI_CR1_BAUDRATE_FPCLK_DIV_4, 
    SPI_CR1_CPOL_CLK_TO_1_WHEN_IDLE,
    SPI_CR1_CPHA_CLK_TRANSITION_2, 
    SPI_CR1_DFF_8BIT, 
    SPI_CR1_MSBFIRST);

  spi_enable_ss_output(SPI1);
  spi_enable(SPI1);

#endif  // EMULATOR
}


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

  // /* Set nOLED_SEL low */
  CLEAR_PIN(nSEL_PIN);

  /* Set nDC low */
  CLEAR_PIN(nDC_PIN);

  spi_send(SPI1, (uint16_t)reg);
  delay_us(10);

  /* Set nOLED_SEL high */
  SET_PIN(nSEL_PIN);

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

  delay_ms(10);
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

  SET_PIN(nRESET_PIN);
  SET_PIN(nDC_PIN);
  SET_PIN(nSEL_PIN);

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
// static void display_configure_io(void) {
void display_configure_io(void) {
#ifndef EMULATOR
  spi_setup();
  /* Set up port C  OLED_RST=PC3, DC=PC2, CS=C1*/
  gpio_mode_setup(GPIOC, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE,
    GPIO1 | GPIO2 | GPIO3 | GPIO5);

  gpio_set_output_options(GPIOC, GPIO_OTYPE_PP, GPIO_OSPEED_100MHZ,
    GPIO1 | GPIO2 | GPIO3 | GPIO5);

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
  // svc_disable_interrupts();

  // /* Set nOLED_SEL low */
  CLEAR_PIN(nSEL_PIN);

  /* Set nDC high */
  SET_PIN(nDC_PIN);

  spi_send(SPI1, (uint16_t)val);
  delay_us(10);

  /* Set nOLED_SEL high */
  SET_PIN(nSEL_PIN);

  // svc_enable_interrupts();

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
  led_func(TGL_GREEN_LED);

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
  // SET_PIN(BACKLIGHT_PWR_PIN);

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

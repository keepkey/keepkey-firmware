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

/* === Includes ============================================================ */

#include <stdint.h>

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/cm3/scb.h>
#include <libopencm3/stm32/spi.h>
#include <libopencm3/stm32/f2/rng.h>
#include <libopencm3/stm32/f2/crc.h>
#include <libopencm3/cm3/cortex.h>

#include "keepkey_board.h"
#include <rng.h>

/* === Variables =========================================================== */

/* Stack smashing protector (SSP) canary value storage */
uintptr_t __stack_chk_guard;

/* === Functions =========================================================== */

/*
 * system_halt() - System halt
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void __attribute__((noreturn)) system_halt(void)
{
    cm_disable_interrupts();

    for(;;);  /* Loops forever */
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
__attribute__((noreturn)) void __stack_chk_fail(void)
{
    layout_warning_static("Error Detected.  Reboot Device!");
    system_halt();
}

/*
 * board_reset() - Request board reset
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void board_reset(void)
{
    scb_reset_system();
}

/*
 * reset_rng() - Reset random number generator
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void reset_rng(void)
{
    /* disable RNG */
    RNG_CR &= ~(RNG_CR_IE | RNG_CR_RNGEN);
    /* reset Seed/Clock/ error status */
    RNG_SR &= ~(RNG_SR_SEIS | RNG_SR_CEIS);
    /* reenable RNG */
    RNG_CR |= RNG_CR_IE | RNG_CR_RNGEN;
    /* this delay is required before rng data can be read */
    delay_us(5);

    /* chuck the 1st random number per FIPS 140-2 */ 
    random32();
}

/*
 * board_init() - Initialize board
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void board_init(void)
{
    timer_init();
    keepkey_leds_init();
    keepkey_button_init();
    layout_init(display_canvas_init());
}

/* calc_crc32() - Calculate crc32 for block of memory
 *
 * INPUT
 *     none
 * OUTPUT
 *     crc32 of data
 */
uint32_t calc_crc32(uint32_t *data, int word_len)
{
    uint32_t crc32 = 0;

    crc_reset();
    crc32 = crc_calculate_block(data, word_len);
    return(crc32);
}

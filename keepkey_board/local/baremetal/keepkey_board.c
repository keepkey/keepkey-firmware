/* START KEEPKEY LICENSE */
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
 *
 */
/* END KEEPKEY LICENSE */

#include <stdint.h>

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/cm3/scb.h>
#include <libopencm3/stm32/spi.h>
#include <libopencm3/stm32/f2/rng.h>
#include <keepkey_board.h>

/* Static and Global variables */

/* stack smashing protector (SSP) canary value storage 
 * initialize to a value until random generator has been setup*/
uintptr_t __stack_chk_guard = 0x1A2B3C4D;  

/*
 * __stack_chk_fail() - stack smashing protector (SSP) call back funcation for -fstack-protector-all GCC option
 *
 * INPUT  - none
 * OUTPUT - none
 */
__attribute__((noreturn)) void __stack_chk_fail(void)
{
    int cnt = 0;
	layout_warning("Error Dectected.  Reboot Device!");
    display_refresh();
	do{
        if(cnt % 5 == 0) {
            animate();
            display_refresh();
        }
    }while(1); //loop forever
}

/*
 * board_reset() - Request board reset
 *
 * INPUT  - none
 * OUTPUT - none
 */
void board_reset(void)
{
    scb_reset_system();
}
 
/*
 * reset_rng(void) - reset random number generator
 *
 * INPUT - none
 * OUTPUT - none
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
}

/*
 * board_init() - Initialize board
 *
 * INPUT - none
 * OUTPUT - none
 */
void board_init(void)
{
    timer_init();
    keepkey_leds_init();
    keepkey_button_init();
    layout_init(display_canvas_init());
}

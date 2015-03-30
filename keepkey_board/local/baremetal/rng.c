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
 *
 *
 *          --------------------------------------------
 * March 30, 2015 - This file has been modified and adapted for KeepKey project.
 */

#include <libopencm3/cm3/common.h>
#include <libopencm3/stm32/memorymap.h>
#include <libopencm3/stm32/f2/rng.h>
#include <rng.h>
#include <keepkey_board/public/timer.h>

uint32_t random32(void)
{
    uint32_t rng_samples = 0, rng_sr_img;
    static uint32_t last = 0, new = 0;

    while (new == last) {
        /* Capture the RNG status register */
        rng_sr_img = RNG_SR;  
        if ((rng_sr_img & (RNG_SR_SEIS | RNG_SR_CEIS)) == 0) {
            if (rng_sr_img & RNG_SR_DRDY) {
                new = RNG_DR;
            }
        }
        else if ((rng_sr_img & (RNG_SR_SECS | RNG_SR_CECS)) == 0) {
            /* Reset RNG interrupt status bits (SECS, CECS errors no longer exist) */
            RNG_SR &= ~(RNG_SR_SEIS | RNG_SR_CEIS);
        }
        else {
            /* RNG is not ready.  Allow few more samples for RNG to come back alive
             * before resetting */
            if (++rng_samples >= 100) {
                /* RNG in hang state.  Reset RNG */
                reset_rng();
                rng_samples = 0;
            }
        }
    }
    last = new;
    return new;
}

void random_buffer(uint8_t *buf, size_t len)
{
	size_t i;
	uint32_t r = 0;
	for (i = 0; i < len; i++) {
		if (i % 4 == 0) {
			r = random32();
		}
		buf[i] = (r >> ((i % 4) * 8)) & 0xFF;
	}
}

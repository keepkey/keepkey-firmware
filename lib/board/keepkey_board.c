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

#ifndef EMULATOR
#  include <libopencm3/stm32/rcc.h>
#  include <libopencm3/stm32/gpio.h>
#  include <libopencm3/cm3/scb.h>
#  include <libopencm3/stm32/spi.h>
#  include <libopencm3/stm32/f2/rng.h>
#  include <libopencm3/stm32/f2/crc.h>
#  include <libopencm3/cm3/cortex.h>
#endif

#include "keepkey/board/keepkey_board.h"
#include "keepkey/rand/rng.h"

#include <stdint.h>
#include <stdlib.h>

/* === Variables =========================================================== */

/* Stack smashing protector (SSP) canary value storage */
uintptr_t __stack_chk_guard;

/* === Functions =========================================================== */

#ifdef EMULATOR
/**
 * \brief System Halt
 */
void __attribute__((noreturn)) shutdown(void)
{
    exit(1);
}
#endif


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
    shutdown();
}

#ifndef EMULATOR
/// Non-maskable interrupt handler
void nmi_handler(void)
{
    // Look for the clock instability interrupt. This is a security measure
    // that helps prevent clock glitching.
    if ((RCC_CIR & RCC_CIR_CSSF) != 0) {
        layout_warning_static("Clock instability detected. Reboot Device!");
        shutdown();
    }
}
#endif

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
#ifndef EMULATOR
    scb_reset_system();
#endif
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

#ifndef EMULATOR
    // Enable Clock Security System
    rcc_css_enable();
#endif

    keepkey_leds_init();
    keepkey_button_init();
    layout_init(display_canvas_init());
}

#ifdef EMULATOR
/// Reverses (reflects) bits in a 32-bit word.
/// http://www.hackersdelight.org/hdcodetxt/crc.c.txt
static uint32_t reverse(unsigned x) {
   x = ((x & 0x55555555) <<  1) | ((x >>  1) & 0x55555555);
   x = ((x & 0x33333333) <<  2) | ((x >>  2) & 0x33333333);
   x = ((x & 0x0F0F0F0F) <<  4) | ((x >>  4) & 0x0F0F0F0F);
   x = (x << 24) | ((x & 0xFF00) << 8) |
       ((x >> 8) & 0xFF00) | (x >> 24);
   return x;
}
#endif

/* calc_crc32() - Calculate crc32 for block of memory
 *
 * INPUT
 *     none
 * OUTPUT
 *     crc32 of data
 */
uint32_t calc_crc32(const void *data, int word_len)
{
    uint32_t crc32 = 0;

#ifndef EMULATOR
    crc_reset();
    crc32 = crc_calculate_block((uint32_t*)data, word_len);
#else
    /// http://www.hackersdelight.org/hdcodetxt/crc.c.txt
    crc32 = 0xFFFFFFFF;
    for (size_t i = 0; i < word_len; i++) {
       uint32_t byte = ((const char *)data)[i];  // Get next byte.
       byte = reverse(byte);                     // 32-bit reversal.
       for (int j = 0; j <= 7; j++) {            // Do eight times.
          if ((int)(crc32 ^ byte) < 0)
               crc32 = (crc32 << 1) ^ 0x04C11DB7;
          else crc32 = crc32 << 1;
          byte = byte << 1;                      // Ready next msg bit.
       }
    }
    crc32 = reverse(~crc32);
#endif

    return crc32;
}


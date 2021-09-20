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

#include <libopencm3/stm32/timer.h>
#include <libopencm3/stm32/f2/nvic.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/cm3/cortex.h>

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/supervise.h"
#include "keepkey/rand/rng.h"

#include <stddef.h>

static volatile uint32_t remaining_delay = UINT32_MAX;
static volatile uint64_t clock = 0;

uint64_t get_clock_ms(void) {
  return clock;
}

/*
 * timer_init() - Timer 4 initialization.  Main timer for round robin tasking.
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void timer_init(void) {
  // Set up the timer.
  rcc_periph_reset_pulse(RST_TIM4);
  timer_enable_irq(TIM4, TIM_DIER_UIE);
  timer_set_mode(TIM4, TIM_CR1_CKD_CK_INT, TIM_CR1_CMS_EDGE, TIM_CR1_DIR_UP);

  /* 1000 * ( 120 / 12000000 ) = 1 ms intervals,
  where 1000 is the counter, 120 is the prescalar,
  and 12000000 is the clks/second */
  timer_set_prescaler(TIM4, 120000);
  timer_set_period(TIM4, 1);

  nvic_set_priority(NVIC_TIM4_IRQ, 16 * 2);

  timer_enable_counter(TIM4);
}

uint32_t fi_defense_delay(volatile uint32_t value) {
  int wait = random32() & 0x4fff;
  volatile int i = 0;
  volatile int j = wait;
  while (i < wait) {
    if (i + j != wait) {
      shutdown_with_error(SHUTDOWN_ERROR_FI_DEFENSE);
    }
    ++i;
    --j;
  }
  // Double-check loop completion.
  if (i != wait || j != 0) {
    shutdown_with_error(SHUTDOWN_ERROR_FI_DEFENSE);
  }
  return value;
}

/*
 * delay_us() - Micro second delay
 *
 * INPUT
 *     - us: count in micro seconds
 * OUTPUT
 *     none
 */
void delay_us(uint32_t us) {
  uint32_t cnt = us * 20;

  while (cnt--) {
    __asm__("nop");
  }
}

/*
 * delay_ms() - Millisecond delay
 *
 * INPUT
 *     - ms: count in milliseconds
 * OUTPUT
 *     none
 */
void delay_ms(uint32_t ms) {
  if (interruptLockoutCounter > 0) {
    delay_us(ms * 1000);
  } else {
    remaining_delay = ms;
    while (remaining_delay > 0) { }
  }
}

/*
 * timerisr_usr() - Timer 4 user mode interrupt service routine
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
void timerisr_usr(void) {
  /* Increment the clock */
  clock++;

  /* Decrement the delay */
  if (remaining_delay > 0) remaining_delay--;

  svc_tusr_return();  // this MUST be called last to properly clean up and
                      // return
}

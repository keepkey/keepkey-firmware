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
#include <libopencm3/stm32/timer.h>
#ifdef DEV_DEBUG
#include <libopencm3/stm32/f4/nvic.h>
#else
#include <libopencm3/stm32/f2/nvic.h>
#endif
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/cm3/cortex.h>
#else
#include <signal.h>
#include <unistd.h>
#endif

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_leds.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/supervise.h"
#include "hwcrypto/crypto/rand.h"

#ifdef DEV_DEBUG
#include "keepkey/board/pin.h"
#endif

#include <stddef.h>

static volatile uint32_t remaining_delay = UINT32_MAX;
static volatile uint32_t timeSinceWakeup = 0;
static RunnableNode runnables[MAX_RUNNABLES];
static RunnableQueue free_queue = {NULL, 0};
static RunnableQueue active_queue = {NULL, 0};

/*
 * runnable_queue_peek() - Get pointer to head node in task manager (queue)
 *
 * INPUT
 *     - queue: head pointer to linklist (queue)
 * OUTPUT
 *     head node in the queue
 */
static RunnableNode *runnable_queue_peek(RunnableQueue *queue) {
  return (queue->head);
}

/*
 * runnable_queue_get() - Get the pointer to node that contains the
 * callback function (task)
 *
 * INPUT
 *     - queue: head pointer to linklist (queue)
 *     - callback: task function
 * OUTPUT
 *     pointer to a node containing the requested task function
 */
static RunnableNode *runnable_queue_get(RunnableQueue *queue,
                                        Runnable callback) {
  RunnableNode *current = queue->head;
  RunnableNode *result = NULL;

  /* check queue is empty */
  if (current != NULL) {
    if (current->runnable == callback) {
      result = current;
      queue->head = current->next;
    } else {
      /* search through the linklist for node that contains the runnable
         callback function */
      RunnableNode *previous = current;
      current = current->next;

      while ((current != NULL) && (result == NULL)) {
        // Found the node!
        if (current->runnable == callback) {
          result = current;
          previous->next = current->next;
          result->next = NULL;
        }

        previous = current;
        current = current->next;
      }
    }
  }

  if (result != NULL) {
    queue->size -= 1;
  }

  return (result);
}

/*
 * runnable_queue_push() - Push node to the task manger (queue)
 *
 * INPUT
 *     - queue: head pointer to the queue
 *     - node: pointer to a new node to be added
 * OUTPUT
 *     none
 */
static void runnable_queue_push(RunnableQueue *queue, RunnableNode *node) {
#ifndef EMULATOR
  svc_disable_interrupts();
#endif

  if (queue->head != NULL) {
    node->next = queue->head;
  } else {
    node->next = NULL;
  }

  queue->head = node;
  queue->size += 1;

#ifndef EMULATOR
  svc_enable_interrupts();
#endif
}

/*
 * runnable_queue_pop() - Pop node from task manager (queue)
 *
 * INPUT
 *     - queue: head pointer to task manager
 * OUTPUT
 *     pointer to an available node retrieved from the queue
 */
static RunnableNode *runnable_queue_pop(RunnableQueue *queue) {
#ifndef EMULATOR
  svc_disable_interrupts();
#endif

  RunnableNode *runnable_node = queue->head;

  if (runnable_node != NULL) {
    queue->head = runnable_node->next;
    queue->size -= 1;
  }

#ifndef EMULATOR
  svc_enable_interrupts();
#endif

  return (runnable_node);
}

/*
 * run_runnables() - Run task (callback function) located in task manager
 * (queue)
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
static void run_runnables(void) {
  // Do timer function work.
  RunnableNode *runnable_node = runnable_queue_peek(&active_queue);

  while (runnable_node != NULL) {
    RunnableNode *next = runnable_node->next;

    if (runnable_node->remaining != 0) {
      runnable_node->remaining -= 1;
    }

    if (runnable_node->remaining == 0) {
      if (runnable_node->runnable != NULL) {
        runnable_node->runnable(runnable_node->context);
      }

      if (runnable_node->repeating) {
        runnable_node->remaining = runnable_node->period;
      } else {
        runnable_queue_push(
            &free_queue,
            runnable_queue_get(&active_queue, runnable_node->runnable));
      }
    }

    runnable_node = next;
  }
}

void kk_timer_init(void) {
  for (int i = 0; i < MAX_RUNNABLES; i++) {
    runnable_queue_push(&free_queue, &runnables[i]);
  }
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
  int i;

  for (i = 0; i < MAX_RUNNABLES; i++) {
    runnable_queue_push(&free_queue, &runnables[i]);
  }

#ifndef EMULATOR
  // Set up the timer.
  rcc_periph_reset_pulse(RST_TIM4);
  timer_set_mode(TIM4, TIM_CR1_CKD_CK_INT, TIM_CR1_CMS_EDGE, TIM_CR1_DIR_UP);

#ifdef DEV_DEBUG
  /* set prescaler 
     2*rcc_apb1_frequency is the internal clock freq for this timer, set for 10khz
  */
  timer_set_prescaler(TIM4, 2*rcc_apb1_frequency/10000);
  timer_set_period(TIM4, 10);  // set for a timer period of 5 khz (empirically determined)

  // initialize scope trig here
  pin_init_output(&SCOPE_PIN, PUSH_PULL_MODE, NO_PULL_MODE);

#else
  /* 1000 * ( 120 / 12000000 ) = 1 ms intervals,
  where 1000 is the counter, 120 is the prescalar,
  and 12000000 is the clks/second 
  THIS IS INCORRECT, PRESCALER CAN ONLY BE A 16 BIT NUMBER*/
  timer_set_prescaler(TIM4, 120000);
  timer_set_period(TIM4, 1);
#endif // DEV_DEBUG

  nvic_set_priority(NVIC_TIM4_IRQ, 16 * 2);

  timer_enable_counter(TIM4);
  timer_enable_irq(TIM4, TIM_DIER_UIE);

#else //EMULATOR
  void tim4_sighandler(int sig);
  signal(SIGALRM, tim4_sighandler);
  ualarm(1000, 1000);
#endif // EMULATOR
}

uint32_t fi_defense_delay(volatile uint32_t value) {
#ifndef EMULATOR
  int wait = random32() & 0x4fff;
  volatile int i = 0;
  volatile int j = wait;
  while (i < wait) {
    if (i + j != wait) {
      shutdown();
    }
    ++i;
    --j;
  }
  // Double-check loop completion.
  if (i != wait || j != 0) {
    shutdown();
  }
#endif
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
#ifndef EMULATOR
#ifdef DEV_DEBUG
uint32_t cnt = us * 28;   // 168Mhz clock
#else
uint32_t cnt = us * 20;
#endif

  while (cnt--) {
    __asm__("nop");
  }
#else
  usleep(us);
#endif
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
#ifdef DEV_DEBUG
remaining_delay = 2*ms;   // this is mult by 2 for 5Mhz clock
#else
remaining_delay = ms;   // this is mult by 2 for 5Mhz clock
#endif

  while (remaining_delay > 0) {
  }
}

/*
 * delay_ms_with_callback() - Millisecond delay allowing a callback for extra
 * work
 *
 * INPUT
 *     - ms: count in milliseconds
 *     - callback_func: function to call during loops
 *     - frequency_ms: frequency in ms to do callback
 * OUTPUT
 *     none
 */
void delay_ms_with_callback(uint32_t ms, callback_func_t callback_func,
                            uint32_t frequency_ms) {
  remaining_delay = ms;

  while (remaining_delay > 0) {
    if (remaining_delay % frequency_ms == 0) {
      (*callback_func)();
    }
  }
}

/*
 * getSysTime() - return number of milliseconds since wakeup
 *
 * INPUT
 * OUTPUT
 *     ms since wakeup
 */
uint32_t getSysTime(void) {
  return timeSinceWakeup;
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
  /* Decrement the delay */
  if (remaining_delay > 0) {
    remaining_delay--;
  }

  // current power-on epoch. Rolls over every 1000+ hours
  timeSinceWakeup++;

  run_runnables();

#ifndef EMULATOR

  svc_tusr_return();  // this MUST be called last to properly clean up and
                      // return
#endif  // EMULATOR
}

#ifdef EMULATOR
void tim4_sighandler(int sig) { timerisr_usr(); }
#endif

/*
 * post_delayed() - Add delay to existing task (callback function) in task
 * manager (queue)
 *
 * INPUT
 *     - callback: task function
 *     - context: pointer to task arguments
 *     - delay_ms: delay befor task starts
 * OUTPUT
 *     none
 */
void post_delayed(Runnable callback, void *context, uint32_t delay_ms) {
  RunnableNode *runnable_node = runnable_queue_get(&active_queue, callback);

  if (runnable_node == NULL) {
    runnable_node = runnable_queue_pop(&free_queue);
  }

  runnable_node->runnable = callback;
  runnable_node->context = context;
  runnable_node->remaining = delay_ms;
  runnable_node->period = 0;
  runnable_node->repeating = false;
  runnable_queue_push(&active_queue, runnable_node);
}

/*
 * post_periodic() - Add repeat and delay to existing task (callback function)
 * in task manager (queue)
 *
 * INPUT
 *     - callback: task function
 *     - context: pointer to task arguments
 *     - period_m: task repeat interval (period)
 *     - delay_ms: delay befor task starts
 * OUTPUT
 *     none
 */
void post_periodic(Runnable callback, void *context, uint32_t period_ms,
                   uint32_t delay_ms) {
  RunnableNode *runnable_node = runnable_queue_get(&active_queue, callback);

  if (runnable_node == NULL) {
    runnable_node = runnable_queue_pop(&free_queue);
  }

  runnable_node->runnable = callback;
  runnable_node->context = context;
  runnable_node->remaining = delay_ms;
  runnable_node->period = period_ms;
  runnable_node->repeating = true;

  runnable_queue_push(&active_queue, runnable_node);
}

/*
 * remove_runnable() - Remove task from the task manager (queue)
 *
 * INPUT
 *     - callback: task function
 * OUTPUT
 *     none
 */
void remove_runnable(Runnable callback) {
  RunnableNode *runnable_node = runnable_queue_get(&active_queue, callback);

  if (runnable_node != NULL) {
    runnable_queue_push(&free_queue, runnable_node);
  }
}

/*
 * clear_runnables() - Reset free_queue and active_queue to initial state
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void clear_runnables(void) {
  RunnableNode *runnable_node = runnable_queue_pop(&active_queue);

  while (runnable_node != NULL) {
    runnable_queue_push(&free_queue, runnable_node);
    runnable_node = runnable_queue_pop(&active_queue);
  }
}

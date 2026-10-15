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
#include <libopencm3/stm32/f2/nvic.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/cm3/cortex.h>
#else
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN /* exclude winsock.h — it declares \
                               shutdown(SOCKET,int) */
#include <windows.h>        /* Sleep() */
#else
#include <signal.h>
#include <time.h>
#include <unistd.h>
#endif
#endif

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_leds.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/supervise.h"
#include "trezor/crypto/rand.h"

#include <stddef.h>
#include <string.h>

static volatile uint32_t remaining_delay = UINT32_MAX;
static volatile uint32_t timeSinceWakeup = 0;
#ifdef EMULATOR
/* Windows has no SIGALRM; the POSIX shared library opts in at initialization.
 * Leave signal-driven callers, including native test harnesses, unchanged. */
#ifdef _WIN32
static bool poll_driven_timer = true;
#else
static bool poll_driven_timer = false;
#endif
void timer_set_poll_driven(bool enabled) { poll_driven_timer = enabled; }
#endif
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
static RunnableNode* runnable_queue_peek(const RunnableQueue* queue) {
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
static RunnableNode* runnable_queue_get(RunnableQueue* queue,
                                        Runnable callback) {
  RunnableNode* current = queue->head;
  RunnableNode* result = NULL;

  /* check queue is empty */
  if (current != NULL) {
    if (current->runnable == callback) {
      result = current;
      queue->head = current->next;
    } else {
      /* search through the linklist for node that contains the runnable
         callback function */
      RunnableNode* previous = current;
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
static void runnable_queue_push(RunnableQueue* queue, RunnableNode* node) {
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
static RunnableNode* runnable_queue_pop(RunnableQueue* queue) {
#ifndef EMULATOR
  svc_disable_interrupts();
#endif

  RunnableNode* runnable_node = queue->head;

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
  RunnableNode* runnable_node = runnable_queue_peek(&active_queue);

  while (runnable_node != NULL) {
    RunnableNode* next = runnable_node->next;

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

/* A second session must not relink nodes still queued from the first. */
static void reset_runnable_queues(void) {
#ifndef EMULATOR
  svc_disable_interrupts();
#endif
  free_queue.head = NULL;
  free_queue.size = 0;
  active_queue.head = NULL;
  active_queue.size = 0;
  memset(runnables, 0, sizeof(runnables));
  remaining_delay = UINT32_MAX;
  timeSinceWakeup = 0;
  for (int i = 0; i < MAX_RUNNABLES; i++) {
    runnables[i].next = free_queue.head;
    free_queue.head = &runnables[i];
    free_queue.size++;
  }
#ifndef EMULATOR
  svc_enable_interrupts();
#endif
}

void kk_timer_init(void) { reset_runnable_queues(); }

#if defined(EMULATOR) && !defined(_WIN32)
/* The standalone process owns SIGALRM. Start it after board initialization,
 * preserving the animation callbacks that layout_init() already registered. */
void timer_start_emulator_signals(void) {
  poll_driven_timer = false;
  void tim4_sighandler(int sig);
  signal(SIGALRM, tim4_sighandler);
  ualarm(1000, 1000);
}
#endif

/*
 * timer_init() - Timer 4 initialization.  Main timer for round robin tasking.
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void timer_init(void) {
  reset_runnable_queues();

#ifndef EMULATOR
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
#elif !defined(_WIN32)
  timer_start_emulator_signals();
#endif
  /* _WIN32: no SIGALRM/ualarm — libkkemu's kkemu_poll() drives timerisr_usr().
   */
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
  uint32_t cnt = us * 20;

  while (cnt--) {
    __asm__("nop");
  }
#elif defined(_WIN32)
  /* Sleep has millisecond resolution. Round up without overflowing us. */
  Sleep(us / 1000u + (us % 1000u != 0u));
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
#ifdef EMULATOR
static uint64_t tick_due_ms;

static uint64_t monotonic_ms(void) {
#ifdef _WIN32
  return GetTickCount64();
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
}
#endif

/* A delay reached inside usbPoll() must drive its own ticks when the outer
 * poll loop is the clock source. Tick once per elapsed wall-clock millisecond
 * and catch up after an oversleep, so a delay lasts as long as it says on a
 * slow host. Never add ticks to the standalone SIGALRM clock, or to the
 * hardware interrupt clock. */
static void delay_start(void) {
#ifdef EMULATOR
  tick_due_ms = monotonic_ms() + 1;
#endif
}

static void delay_tick(void) {
#ifdef EMULATOR
  if (poll_driven_timer) {
    uint64_t now = monotonic_ms();
    if (now < tick_due_ms) {
#ifdef _WIN32
      Sleep((DWORD)(tick_due_ms - now));
#else
      usleep((useconds_t)((tick_due_ms - now) * 1000u));
#endif
    }
    tick_due_ms++;
    timerisr_usr();
  }
#endif
}

void delay_ms(uint32_t ms) {
  remaining_delay = ms;
  delay_start();

  while (remaining_delay > 0) {
    delay_tick();
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
  delay_start();

  while (remaining_delay > 0) {
    if (remaining_delay % frequency_ms == 0) {
      (*callback_func)();
    }
    delay_tick();
  }
}

/*
 * getSysTime() - return number of milliseconds since wakeup
 *
 * INPUT
 * OUTPUT
 *     ms since wakeup
 */
uint32_t getSysTime(void) { return timeSinceWakeup; }

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
#endif
}

#if defined(EMULATOR) && !defined(_WIN32)
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
void post_delayed(Runnable callback, void* context, uint32_t delay_ms) {
  RunnableNode* runnable_node = runnable_queue_get(&active_queue, callback);

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
void post_periodic(Runnable callback, void* context, uint32_t period_ms,
                   uint32_t delay_ms) {
  RunnableNode* runnable_node = runnable_queue_get(&active_queue, callback);

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
  RunnableNode* runnable_node = runnable_queue_get(&active_queue, callback);

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
  RunnableNode* runnable_node = runnable_queue_pop(&active_queue);

  while (runnable_node != NULL) {
    runnable_queue_push(&free_queue, runnable_node);
    runnable_node = runnable_queue_pop(&active_queue);
  }
}

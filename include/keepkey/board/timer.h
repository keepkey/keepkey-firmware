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

#ifndef TIMER_H
#define TIMER_H


#include <stdint.h>
#include <stdbool.h>


#define ONE_SEC         1100    /* Count for 1 second  */
#define HALF_SEC        500     /* Count for 0.5 second */
#define MAX_RUNNABLES   3       /* Max number of queue for task manager */


typedef void (*callback_func_t)(void);
typedef void (*Runnable)(void *context);
typedef struct RunnableNode RunnableNode;

struct RunnableNode
{
    uint32_t    remaining;
    Runnable    runnable;
    void        *context;
    uint32_t    period;
    bool        repeating;
    RunnableNode *next;
};

typedef struct
{
    RunnableNode   *head;
    int             size;
} RunnableQueue;


void timerisr_usr(void);

/**
 * kk_timer_init() - Timer 4 initialization.  Main timer for round robin tasking.
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 **/
void kk_timer_init(void);

void timer_init(void);
void delay_ms(uint32_t ms);
void delay_us(uint32_t us);
void delay_ms_with_callback(uint32_t ms, callback_func_t callback_func,
                            uint32_t frequency_ms);
void post_delayed(Runnable runnable, void *context, uint32_t ms_delay);
void post_periodic(Runnable runnable, void *context, uint32_t period_ms,
                   uint32_t delay_ms);
void remove_runnable(Runnable runnable);
void clear_runnables(void);

#endif
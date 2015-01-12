/* START KEEPKEY LICENSE */
/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2014 KeepKey LLC
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

//================================ INCLUDES ===================================


#include <stddef.h>
#include "timer.h"
#include <libopencm3/stm32/timer.h>
#include <libopencm3/stm32/f2/nvic.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/cm3/cortex.h>
#include "keepkey_leds.h"


/******************** Static/Global Variables ***************************/ 
static volatile uint32_t remaining_delay;
static RunnableNode runnables[ MAX_RUNNABLES ];
static RunnableQueue free_queue = { NULL, 0 };
static RunnableQueue active_queue = { NULL, 0 };


/***************** Function Declarations ********************************/
static void run_runnables(void);
static void runnable_queue_push( RunnableQueue *queue, RunnableNode *node);
static RunnableNode *runnable_queue_pop(RunnableQueue* queue);
static RunnableNode *runnable_queue_peek(RunnableQueue* queue);
static RunnableNode *runnable_queue_get(RunnableQueue *queue, Runnable callback);

/*
 * timer_init() - timer 4 initialization.  Main timer for round robin tasking. 
 *
 * INPUT - none
 * OUTPUT - none
 */
void timer_init(void) 
{
    int i;
    for( i = 0; i < MAX_RUNNABLES; i++ ) {
        runnable_queue_push( &free_queue, &runnables[ i ] );
    }

    // Set up the timer.
    timer_reset(TIM4);
    timer_enable_irq(TIM4, TIM_DIER_UIE);
    timer_set_mode( TIM4, TIM_CR1_CKD_CK_INT, TIM_CR1_CMS_EDGE, TIM_CR1_DIR_UP );

    // 1000 * ( 120 / 12000000 ) = 1 ms intervals
    // Where 1000 is the counter, 120 is the prescalar,
    // and 12000000 is the clks/second
    timer_set_prescaler( TIM4, 120000 );
    timer_set_period( TIM4, 1 );//5625 );

    nvic_set_priority( NVIC_TIM4_IRQ, 16 * 2 );
    nvic_enable_irq( NVIC_TIM4_IRQ );

    timer_enable_counter( TIM4 );
}

/*
 * delay_ms() - millisecond delay 
 *
 * INPUT - 
 *      ms - count in milliseconds
 * OUTPUT - 
 *      none
 */
void delay_ms(uint32_t ms)
{
    remaining_delay = ms;

    while( remaining_delay > 0 ) {}
}


/*
 * tim4_isr() - timer 4 interrupt service routine
 *
 * INPUT - none
 * OUTPUT - none
 *
 */
void tim4_isr(void)
{
    // Decrement the delay.
    if( remaining_delay > 0 ) {
        remaining_delay--;
    }
    run_runnables();
    timer_clear_flag(TIM4, TIM_SR_UIF);
}


/*
 * run_runnables() - 
 *
 * INPUT - none
 * OUTPUT - none
 */
static void run_runnables(void)
{
    // Do timer function work.    
    RunnableNode* runnable_node = runnable_queue_peek( &active_queue );

    while( runnable_node != NULL )
    {
        RunnableNode* next = runnable_node->next;

        if( runnable_node->remaining != 0 )
        {
            runnable_node->remaining -= 1;
        }

        if( runnable_node->remaining == 0 )
        {
            if( runnable_node->runnable != NULL )
            {
                runnable_node->runnable( runnable_node->context );
            }

            if( runnable_node->repeating )
            {
                runnable_node->remaining = runnable_node->period;
            }
            else
            {
                runnable_queue_push(
                        &free_queue,
                        runnable_queue_get( &active_queue, runnable_node->runnable ) );
            }
        }

        runnable_node = next;
    }
}


/*
 * post_delayed() - 
 *
 * INPUT - 
 *      runnable -
 *      *context - 
 *      delay_ms - 
 * OUTPUT - 
 */
void post_delayed(Runnable runnable, void *context, uint32_t delay_ms)
{
    RunnableNode* runnable_node = runnable_queue_get( &active_queue, runnable );

    if( runnable_node == NULL ) {
        runnable_node = runnable_queue_pop( &free_queue );
    }

    runnable_node->runnable     = runnable;
    runnable_node->context      = context;
    runnable_node->remaining    = delay_ms;
    runnable_node->period       = 0;
    runnable_node->repeating    = false;

    runnable_queue_push( &active_queue, runnable_node );
}


/*
 * post_periodic() - 
 *
 * INPUT - 
 *      callbac - 
 *      *contex - 
 *      period_m - 
 *      delay_ms - 
 * OUTPUT - 
 */
void post_periodic(Runnable callback, void *context, uint32_t period_ms, uint32_t delay_ms)
{
    RunnableNode* runnable_node = runnable_queue_get( &active_queue, callback );
    if( runnable_node == NULL ) {
        runnable_node = runnable_queue_pop( &free_queue );
    }

    runnable_node->runnable     = callback;
    runnable_node->context      = context;
    runnable_node->remaining    = delay_ms;
    runnable_node->period       = period_ms;
    runnable_node->repeating    = true;

    runnable_queue_push( &active_queue, runnable_node );
}


/*
 * remove_runnable() - 
 *
 * INPUT - 
 *      runnable - 
 * OUTPUT - 
 *
 */
void remove_runnable(Runnable runnable)
{
    RunnableNode* runnable_node = runnable_queue_get( &active_queue, runnable );

    if( runnable_node != NULL ) {
        runnable_queue_push( &free_queue, runnable_node );
    }
}


/*
 * clear_runnables() - 
 *
 * INPUT - none
 * OUTPUT - none
 */
void clear_runnables(void)
{
    RunnableNode* runnable_node = runnable_queue_pop( &active_queue );

    while( runnable_node != NULL ) {
        runnable_queue_push(&free_queue, runnable_node);
        runnable_node = runnable_queue_pop(&active_queue);
    }
}


/*
 * runnable_queue_peek() - 
 *
 * INPUT - 
 *      *queue - 
 * OUTPUT - 
 *      *RunnableNode - 
 */
static RunnableNode* runnable_queue_peek(RunnableQueue *queue)
{
    return queue->head;
}


/*
 * runnable_queue_push() - 
 *
 * INPUT -
 * OUTPUT - 
 *      *queu - 
 *      *node - 
 */
static void runnable_queue_push(RunnableQueue *queue, RunnableNode *node)
{
    cm_disable_interrupts();
    if( queue->head != NULL ) {
        node->next = queue->head;
    } else {
    	node->next = NULL;
    }
    queue->head = node;
    queue->size += 1;
    cm_enable_interrupts();
}


/*
 * runnable_queue_pop() - 
 *
 * INPUT - 
 *      *queue -
 * OUTPUT -
 *      *RunnableNode 
 */
static RunnableNode* runnable_queue_pop(RunnableQueue *queue)
{
    cm_disable_interrupts();

    RunnableNode* runnable_node = queue->head;

    if( runnable_node != NULL )
    {
        queue->head = runnable_node->next;
        queue->size -= 1;
    }

    cm_enable_interrupts();

    return runnable_node;
}


/*
 * runnable_queue_get()
 *
 * INPUT -
 *      *queu -
 *      runnable -
 * OUTPUT - 
 *      *RunnableNode
 *
 */
static RunnableNode* runnable_queue_get(RunnableQueue *queue, Runnable runnable)
{
    RunnableNode* current = queue->head;
    RunnableNode* result = NULL;

    if( current != NULL ) {
        if( current->runnable == runnable ) {
            result = current;
            queue->head = current->next;
        } else {
            RunnableNode* previous = current;
            current = current->next;

            while( ( current != NULL ) && ( result == NULL ) ) {
                // Found the node!
                if( current->runnable == runnable ) {
                    result = current;
                    previous->next = current->next;
                    result->next = NULL;
                }

                previous = current;
                current = current->next;
            }
        }
    }

    if( result != NULL ) {
        queue->size -= 1;
    }
    return(result);
}

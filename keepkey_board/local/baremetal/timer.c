/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file timer.c
/// Timer related functions such as delays and delayed runnables.
///


//================================ INCLUDES ===================================


#include <stddef.h>
#include "timer.h"
#include <libopencm3/stm32/timer.h>
#include <libopencm3/stm32/f2/nvic.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/cm3/cortex.h>
#include "keepkey_leds.h"


//====================== CONSTANTS, TYPES, AND MACROS =========================


#define MAX_RUNNABLES 3


//-----------------------------------------------------------------------------
// Delayed function node callback.
//
typedef struct RunnableNode RunnableNode;
struct RunnableNode
{
    uint32_t    remaining;

    Runnable    runnable;
    void*       context;

    uint32_t    period;
    bool        repeating;

    RunnableNode* next;
};


typedef struct
{
    RunnableNode*   head;

    int             size;
} RunnableQueue;



//=============================== VARIABLES ===================================


static volatile uint32_t remaining_delay;


static RunnableNode runnables[ MAX_RUNNABLES ];


static RunnableQueue free_queue = { NULL, 0 };
static RunnableQueue active_queue = { NULL, 0 };


//====================== PRIVATE FUNCTION DECLARATIONS ========================


//-----------------------------------------------------------------------------
// 
static void
run_runnables(
        void
);


//-----------------------------------------------------------------------------
// 
static void
runnable_queue_push(
        RunnableQueue* queue,
        RunnableNode*      node
);


//-----------------------------------------------------------------------------
// 
static RunnableNode*
runnable_queue_pop(
        RunnableQueue* queue
);


//-----------------------------------------------------------------------------
// 
static RunnableNode*
runnable_queue_peek(
        RunnableQueue* queue
);


//-----------------------------------------------------------------------------
// 
static RunnableNode*
runnable_queue_get(
        RunnableQueue* queue,
        Runnable callback
);


//=============================== FUNCTIONS ===================================


//-----------------------------------------------------------------------------
// See timer.h for public interface.
//
void
timer_init(
        void
)
{
    int i;
    for( i = 0; i < MAX_RUNNABLES; i++ )
    {
        runnable_queue_push( &free_queue, &runnables[ i ] );
    }

    // Set up the timer.
    timer_reset(TIM4);
    timer_enable_irq(TIM4, TIM_DIER_UIE);
    timer_set_mode(
            TIM4, 
            TIM_CR1_CKD_CK_INT,
            TIM_CR1_CMS_EDGE, 
            TIM_CR1_DIR_UP );

    // 1000 * ( 120 / 12000000 ) = 1 ms intervals
    // Where 1000 is the counter, 120 is the prescalar,
    // and 12000000 is the clks/second
    timer_set_prescaler( TIM4, 120000 );
    timer_set_period( TIM4, 1 );//5625 );

    nvic_set_priority( NVIC_TIM4_IRQ, 16 * 2 );
    nvic_enable_irq( NVIC_TIM4_IRQ );

    timer_enable_counter( TIM4 );
}


//-----------------------------------------------------------------------------
// See timer.h for public interface.
//
void
delay(
        uint32_t ms
)
{
    remaining_delay = ms;

    while( remaining_delay > 0 )
    {}
}


//-----------------------------------------------------------------------------
// 
void tim4_isr()
{
    // Decrement the delay.
    if( remaining_delay > 0 )
    {
        remaining_delay--;
    }
    
    run_runnables();

    timer_clear_flag(TIM4, TIM_SR_UIF);

}


//-----------------------------------------------------------------------------
// 
static void
run_runnables(
        void
)
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


//-----------------------------------------------------------------------------
// 
void
post_delayed(
        Runnable    runnable,
        void*       context,
        uint32_t    delay_ms
)
{
    RunnableNode* runnable_node = runnable_queue_get( &active_queue, runnable );

    if( runnable_node == NULL )
    {
        runnable_node = runnable_queue_pop( &free_queue );
    }

    runnable_node->runnable     = runnable;
    runnable_node->context      = context;
    runnable_node->remaining    = delay_ms;
    runnable_node->period       = 0;
    runnable_node->repeating    = false;

    runnable_queue_push( &active_queue, runnable_node );
}


//-----------------------------------------------------------------------------
// 
void
post_periodic(
        Runnable    callback,
        void*       context,
        uint32_t    period_ms,
        uint32_t    delay_ms
)
{
    RunnableNode* runnable_node = runnable_queue_get( &active_queue, callback );

    if( runnable_node == NULL )
    {
        runnable_node = runnable_queue_pop( &free_queue );
    }

    runnable_node->runnable     = callback;
    runnable_node->context      = context;
    runnable_node->remaining    = delay_ms;
    runnable_node->period       = period_ms;
    runnable_node->repeating    = true;

    runnable_queue_push( &active_queue, runnable_node );
}


//-----------------------------------------------------------------------------
// 
void
remove_runnable(
        Runnable  runnable
)
{
    RunnableNode* runnable_node = runnable_queue_get( &active_queue, runnable );

    if( runnable_node != NULL )
    {
        runnable_queue_push( &free_queue, runnable_node );
    }
}


//-----------------------------------------------------------------------------
// 
void
clear_runnables(
        void
)
{
    RunnableNode* runnable_node = runnable_queue_pop( &active_queue );

    while( runnable_node != NULL )
    {
        runnable_queue_push(
                &free_queue,
                runnable_node );

        runnable_node = runnable_queue_pop( &active_queue );
    }
}


//-----------------------------------------------------------------------------
// 
static RunnableNode*
runnable_queue_peek(
        RunnableQueue* queue
)
{
    return queue->head;
}


//-----------------------------------------------------------------------------
// 
static void
runnable_queue_push(
        RunnableQueue* queue,
        RunnableNode*      node
)
{
    cm_disable_interrupts();

    if( queue->head != NULL )
    {
        node->next = queue->head;
    }
    else
    {
    	node->next = NULL;
    }
 
    queue->head = node;
    queue->size += 1;

    cm_enable_interrupts();
}


//-----------------------------------------------------------------------------
// 
static RunnableNode*
runnable_queue_pop(
        RunnableQueue* queue
)
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


//-----------------------------------------------------------------------------
// 
static RunnableNode*
runnable_queue_get(
        RunnableQueue* queue,
        Runnable runnable
)
{
    RunnableNode* current = queue->head;
    RunnableNode* result = NULL;

    if( current != NULL )
    {
        if( current->runnable == runnable )
        {
            result = current;
            queue->head = current->next;
        }
        else
        {
            RunnableNode* previous = current;
            current = current->next;

            while( ( current != NULL ) && ( result == NULL ) )
            {
                // Found the node!
                if( current->runnable == runnable )
                {
                    result = current;
                    previous->next = current->next;
                    result->next = NULL;
                }

                previous = current;
                current = current->next;
            }
        }
    }

    if( result != NULL )
    {
        queue->size -= 1;
    }

    return result;
}

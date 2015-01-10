/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file timer.h


//============================= CONDITIONALS ==================================


#ifndef timer_H
#define timer_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
	

/******************** #defines *************************************/
#define ONE_SEC 1000 
#define HALF_SEC 500
/******************** Typedefs and enums ***************************/
typedef void (*Runnable)(void* context);


/******************** Function Declarations ***********************/
void timer_init(void);
void delay_ms(uint32_t ms);
void post_delayed(Runnable runnable, void *context, uint32_t ms_delay);
void post_periodic(Runnable runnable, void *context, uint32_t period_ms, uint32_t delay_ms);
void remove_runnable(Runnable runnable);
void clear_runnables(void);

#ifdef __cplusplus
}
#endif

#endif // timer_H


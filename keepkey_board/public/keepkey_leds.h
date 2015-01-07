/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file keepkey_leds.h


//============================= CONDITIONALS ==================================


#ifndef keepkey_leds_H
#define keepkey_leds_H

#ifdef __cplusplus
extern "C" {
#endif


//=============================== INCLUDES ====================================


#include <stdint.h>
#include "canvas.h"

/* enums */
typedef enum {
    CLR_GREEN_LED,
    SET_GREEN_LED,
    TGL_GREEN_LED,
    CLR_RED_LED,
    SET_RED_LED,
    TGL_RED_LED
}led_action;

/* Function declarations  */

void keepkey_leds_init( void);
void led_func(led_action act);

#ifdef __cplusplus
}
#endif

#endif // keepkey_leds_H


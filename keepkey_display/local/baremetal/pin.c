/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file pin.c
/// Basic pin functions.
///


//================================ INCLUDES ===================================


#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include "pin.h"


//====================== CONSTANTS, TYPES, AND MACROS =========================


//=============================== VARIABLES ===================================


//====================== PRIVATE FUNCTION DECLARATIONS ========================


//=============================== FUNCTIONS ===================================


//-----------------------------------------------------------------------------
// See pin.h for public interface.
//
void
pin_init_output(
        const Pin*  pin,
        OutputMode  output_mode,
        PullMode    pull_mode
)
{
    uint8_t output_mode_setpoint;
    uint8_t pull_mode_setpoint;

    switch( output_mode )
    {
        case OPEN_DRAIN_MODE:
            output_mode_setpoint = GPIO_OTYPE_OD;
            break;

        case PUSH_PULL_MODE:
        default:
            output_mode_setpoint = GPIO_OTYPE_PP;
            break;
    }

    switch( pull_mode )
    {
        case PULL_UP_MODE:
            pull_mode_setpoint = GPIO_PUPD_PULLUP;
            break;

        case PULL_DOWN_MODE:
            pull_mode_setpoint = GPIO_PUPD_PULLDOWN;
            break;

        case NO_PULL_MODE:
        default:
            pull_mode_setpoint = GPIO_PUPD_NONE;
            break;
    }

    // Set up port A
    gpio_mode_setup( 
            pin->port, 
            GPIO_MODE_OUTPUT, 
            pull_mode_setpoint, 
            pin->pin );

    gpio_set_output_options(
            pin->port,
            output_mode_setpoint,
            GPIO_OSPEED_100MHZ,
            pin->pin );
}
/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file __TemplateFile.h
/// __One_line_description_of_file
///
/// @page __Page_label __Page_title (__TemplateFile.h)
///
/// @section __1st_section_label __1st_section_title
///
/// __Section_body
///
/// @section __2nd_section_label __2nd_section_title
///
/// __Section_body
///
/// @see __Insert_cross_reference_here




//============================= CONDITIONALS ==================================


#ifndef pin_H
#define pin_H

#ifdef __cplusplus
extern "C" {
#endif


//=============================== INCLUDES ====================================


#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>


//====================== CONSTANTS, TYPES, AND MACROS =========================


//-----------------------------------------------------------------------------
// Pin modes.
//
typedef enum
{
    PUSH_PULL_MODE,
    OPEN_DRAIN_MODE,

    NUM_PIN_MODES
} OutputMode;


//-----------------------------------------------------------------------------
// Pull up and pull down modes.
//
typedef enum
{
    PULL_UP_MODE,
    PULL_DOWN_MODE,
    NO_PULL_MODE,

    NUM_PULL_MODES
} PullMode;


//-----------------------------------------------------------------------------
// Information about a pin.
typedef struct
{
    uint32_t port;
    uint16_t pin;

} Pin;


//-----------------------------------------------------------------------------
// Set a pin.
#define SET_PIN(p)      GPIO_BSRR( (p).port ) = (p).pin


//-----------------------------------------------------------------------------
// Clear a pin
#define CLEAR_PIN(p)    GPIO_BSRR( (p).port ) = ( (p).pin << 16 )


//-----------------------------------------------------------------------------
// Toggle a pin
#define TOGGLE_PIN(p)   GPIO_ODR( (p).port ) ^= (p).pin


//=============================== VARIABLES ===================================


//=============================== FUNCTIONS ===================================


//-----------------------------------------------------------------------------
/// Initialize the GPIO necessary for the display and show a blank screen.
///
//-----------------------------------------------------------------------------
void
pin_init_output(
        const Pin*  pin,
        OutputMode  output_mode,
        PullMode    pull_mode
);


#ifdef __cplusplus
}
#endif

#endif // pin_H


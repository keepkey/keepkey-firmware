/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file layout.h


//============================= CONDITIONALS ==================================


#ifndef keepkey_button_H
#define keepkey_button_H

#ifdef __cplusplus
extern "C" {
#endif


//=============================== INCLUDES ====================================


#include <stdint.h>
#include "canvas.h"


//====================== CONSTANTS, TYPES, AND MACROS =========================


typedef void (*Handler)(void* context);


//=============================== VARIABLES ===================================


//=============================== FUNCTIONS ===================================


//-----------------------------------------------------------------------------
/// 
///
//-----------------------------------------------------------------------------
void
keepkey_button_init(
		void
);


//-----------------------------------------------------------------------------
/// 
///
//-----------------------------------------------------------------------------
void keepkey_button_set_on_press_handler( Handler handler, void* context);


//-----------------------------------------------------------------------------
/// 
///
//-----------------------------------------------------------------------------
void keepkey_button_set_on_release_handler( Handler handler, void* context);

/**
 * @return true if the button is currently in the 'down' state.
 */
bool keepkey_button_down(void);

/**
 * @return true if the button is currently in the 'up' state.
 */
bool keepkey_button_up(void);


#ifdef __cplusplus
}
#endif

#endif // keepkey_button_H


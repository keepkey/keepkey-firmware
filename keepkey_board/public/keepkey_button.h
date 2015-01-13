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


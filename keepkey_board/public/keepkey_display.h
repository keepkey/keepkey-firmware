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


#ifndef keepkey_display_H
#define keepkey_display_H

#ifdef __cplusplus
extern "C" {
#endif

#include "canvas.h"

/**************  #defines *******************************/ 
#define KEEPKEY_DISPLAY_HEIGHT 	64
#define KEEPKEY_DISPLAY_WIDTH	256

#define DEFAULT_DISPLAY_BRIGHTNESS 	65 // percent


//=============================== VARIABLES ===================================


/**********************  Function Declarations ***********************/
static void display_configure_io ( void);
static void display_reset_io( void);
static void display_reset( void);
static void display_prepare_gram_write( void);
static void display_write_reg ( uint8_t reg);
static void display_write_ram( uint8_t val );



//-----------------------------------------------------------------------------
/// Initialize the GPIO necessary for the display and show a blank screen.
///
//-----------------------------------------------------------------------------
Canvas*display_init (void);


//-----------------------------------------------------------------------------
/// Initialize the GPIO necessary for the display and show a blank screen.
///
//-----------------------------------------------------------------------------
Canvas*
display_canvas (
        void
);


//-----------------------------------------------------------------------------
/// Initialize the GPIO necessary for the display and show a blank screen.
///
//-----------------------------------------------------------------------------
void
display_refresh(
		void
);


//-----------------------------------------------------------------------------
/// Display settings
///
//-----------------------------------------------------------------------------
void display_set_brightness(int percentage);


//-----------------------------------------------------------------------------
/// Initialize the GPIO necessary for the display and show a blank screen.
///
//-----------------------------------------------------------------------------
void
display_turn_on(
        void
);


//-----------------------------------------------------------------------------
/// Initialize the GPIO necessary for the display and show a blank screen.
///
//-----------------------------------------------------------------------------
void
display_turn_off(
        void
);


#ifdef __cplusplus
}
#endif

#endif // keepkey_display_H


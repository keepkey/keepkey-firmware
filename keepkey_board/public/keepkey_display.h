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


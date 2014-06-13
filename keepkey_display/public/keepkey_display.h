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


//=============================== INCLUDES ====================================


#include "canvas.h"


//====================== CONSTANTS, TYPES, AND MACROS =========================


#define KEEPKEY_DISPLAY_HEIGHT 	64
#define KEEPKEY_DISPLAY_WIDTH	256

#define DEFAULT_DISPLAY_BRIGHTNESS 	65 // percent


//=============================== VARIABLES ===================================


//=============================== FUNCTIONS ===================================


//-----------------------------------------------------------------------------
/// Initialize the GPIO necessary for the display and show a blank screen.
///
//-----------------------------------------------------------------------------
Canvas*
display_init (
        void
);


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
/// Initialize the GPIO necessary for the display and show a blank screen.
///
//-----------------------------------------------------------------------------
void
display_set_brightness(
        int percentage
);


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


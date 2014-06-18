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


#ifndef canvas_H
#define canvas_H

#ifdef __cplusplus
extern "C" {
#endif


//=============================== INCLUDES ====================================


#include <stdint.h>
#include <stdbool.h>


//====================== CONSTANTS, TYPES, AND MACROS =========================


typedef struct
{
	uint8_t* 	buffer;
	int 		height;
	int 		width;
	bool 		dirty;
} Canvas;


//=============================== VARIABLES ===================================


//=============================== FUNCTIONS ===================================


#ifdef __cplusplus
}
#endif

#endif // canvas_H


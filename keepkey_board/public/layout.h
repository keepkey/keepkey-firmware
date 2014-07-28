/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file layout.h


//============================= CONDITIONALS ==================================


#ifndef layout_H
#define layout_H

#ifdef __cplusplus
extern "C" {
#endif


//=============================== INCLUDES ====================================


#include <stdint.h>
#include "canvas.h"


//====================== CONSTANTS, TYPES, AND MACROS =========================


//=============================== VARIABLES ===================================


//=============================== FUNCTIONS ===================================


//-----------------------------------------------------------------------------
/// Initialize the layout subsystem.
///
//-----------------------------------------------------------------------------
void layout_init( Canvas* canvas);


//-----------------------------------------------------------------------------
///
/// @TODO Have some personalization here?
//-----------------------------------------------------------------------------
void layout_home( void);


//-----------------------------------------------------------------------------
///
/// @TODO Have some personalization here?
//-----------------------------------------------------------------------------
void layout_sleep( void);


//-----------------------------------------------------------------------------
///
///
//-----------------------------------------------------------------------------
void layout_tx_info( const char* address, uint64_t amount_in_satoshi);


void layout_confirmation(); 

/**
 * @return the number of characters that are printable across the width of the screen.
 */
uint32_t layout_char_width();

/**
 * Used by the bootloader to verify firmware update.
 *
 * @param confirmation_duration_ms The time we require the user to hold the button for
 *  in order to confirm update.
 */
void layout_firmware_update_confirmation();

/**
 * Standard 2-line notification layout for display.
 */
void layout_standard_notification( const char* str1, const char* str2);

//-----------------------------------------------------------------------------
/// Call this in a loop.
///
//-----------------------------------------------------------------------------
void animate( void); 

typedef enum 
{
    LABEL_COLOR    = 0x44,
    DATA_COLOR     = 0xFF,
} LAYOUT_FONT_COLORS;

/**
 * Layout the text on the specified line given the color.
 *
 * @param line The line id to write on (0-3 for standard oled)
 * @param color The color of the string
 * @param str The string to write.  Any longer than the line and it will be truncated.
 * @param ... optional printf-style varargs 
 */
void layout_line(unsigned int line, uint8_t color, const char *str, ...);

typedef void (*AnimateCallback)(void* data, uint32_t duration, uint32_t elapsed );
void
layout_add_animation(
        AnimateCallback     callback,
        void*               data,
        uint32_t            duration
);

void layout_clear();
void layout_clear_animations();
void layout_clear_static();


#ifdef __cplusplus
}
#endif

#endif // layout_H


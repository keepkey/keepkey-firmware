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
#include "resources.h"


//====================== CONSTANTS, TYPES, AND MACROS =========================

typedef enum
{
	NOTIFICATION_INFO,
    NOTIFICATION_REQUEST,
	NOTIFICATION_RECOVERY,
	NOTIFICATION_UNPLUG,
    NOTIFICATION_CONFIRM_ANIMATION,
    NOTIFICATION_CONFIRMED
} NotificationType;

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
void layout_home(void);


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
uint32_t title_char_width();
uint32_t body_char_width();
uint32_t warning_char_width();

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
void layout_standard_notification( const char* str1, const char* str2, NotificationType type);

/*
 * Standard warning message
 */
void layout_warning(const char* prompt);

/*
 * Standard pin message
 */
void layout_pin(const char *prompt, char *pin);

/*
 * Standard layout for intro
 */
void layout_intro();

/*
 * Standard layout for loading animations that fill entire screen
 */
void layout_loading(AnimationResource type);


//-----------------------------------------------------------------------------
/// Call this in a loop.
///
//-----------------------------------------------------------------------------
void animate( void);

/*
 * Determine if animations exist in active animations queue
 */
bool is_animating(void);

/**
 * Layout the text on the specified line given the color.
 *
 * @param line The line id to write on (0-3 for standard oled)
 * @param color The color of the string
 * @param str The string to write.  Any longer than the line and it will be truncated.
 * @param ... optional printf-style varargs 
 */
void layout_line(unsigned int line, uint8_t color, const char *str, ...);

void force_animation_start(void);
void animating_progress_handler(void);

typedef void (*AnimateCallback)(void* data, uint32_t duration, uint32_t elapsed);
void layout_add_animation(AnimateCallback callback, void* data, uint32_t duration);

void layout_clear();
void layout_clear_animations();
void layout_clear_static();


#ifdef __cplusplus
}
#endif

#endif // layout_H


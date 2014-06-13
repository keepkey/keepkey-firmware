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
void
layout_init(
        Canvas* canvas
);


//-----------------------------------------------------------------------------
///
/// @TODO Have some personalization here?
//-----------------------------------------------------------------------------
void
layout_home(
        void
);


//-----------------------------------------------------------------------------
///
/// @TODO Have some personalization here?
//-----------------------------------------------------------------------------
void
layout_sleep(
        void
);


//-----------------------------------------------------------------------------
///
///
//-----------------------------------------------------------------------------
void
layout_tx_info(
        const char* address,
        uint32_t    amount_in_satoshi
);


//-----------------------------------------------------------------------------
///
///
//-----------------------------------------------------------------------------
void
layout_tx_confirmation(
        uint32_t confirmation_duration_ms
);

/**
 * Used by the bootloader to verify firmware update.
 *
 * @param confirmation_duration_ms The time we require the user to hold the button for
 *  in order to confirm update.
 */
void
layout_firmware_update_confirmation(
        uint32_t confirmation_duration_ms
);

/**
 * Standard 2-line notification layout for display.
 */
void
    layout_standard_notification(
            const char* str1,
            const char* str2
);


//-----------------------------------------------------------------------------
/// Call this in a loop.
///
//-----------------------------------------------------------------------------
void
animate(
        void
);


#ifdef __cplusplus
}
#endif

#endif // layout_H


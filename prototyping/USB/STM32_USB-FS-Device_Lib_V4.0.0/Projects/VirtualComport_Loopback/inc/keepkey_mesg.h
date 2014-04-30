#ifdef KEEPKEY_PROTOTYPE
/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file keepkey_mesg.h
/// USB message interface for Keepkey.
///
/// @page KeepkeyMesg Keepkey USB Message Interface (keepkey_mesg.h)
///
/// This file defines a function interface for sending/receiving
/// USB messages to/from Keepkey.

#ifndef __KEEPKEY_MESG_H
#define __KEEPKEY_MESG_H

#ifdef __cplusplus
extern "C" {
#endif


//============================= CONDITIONALS ==================================


//=============================== INCLUDES ====================================


//====================== CONSTANTS, TYPES, AND MACROS =========================


//=============================== VARIABLES ===================================


//=============================== FUNCTIONS ===================================


//-----------------------------------------------------------------------------
/// Handle message received from host via USB
///
/// This is the top-level function for handling messages received from the
/// host via the USB interface (the OUT endpoint from the host perspective).
///
/// @return Nothing
///
/// @callgraph
/// @callergraph
//-----------------------------------------------------------------------------
void
KK_HandleUsbMessage (
    __IO uint8_t* recv_buffer,      ///< [in] Pointer to endpoint receive buffer
    __IO uint32_t recv_length       ///< [in] Number of characters received
);


#ifdef __cplusplus
}
#endif

#endif // __KEEPKEY_MESG_H

#endif // KEEPKEY_PROTOTYPE

/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file KeepKeyBoard.cpp


//=============================== INCLUDES ====================================
    

#include "KeepKeyBoard.h"
#include <stddef.h>


//=================== CONSTANTS, MACROS, AND TYPES ========================

//============================ VARIABLES ==================================

//====================== CLASSES AND FUNCTIONS ============================


//-------------------------------------------------------------------------
// See declaration for interface.
//
KeepKeyBoard::KeepKeyBoard(
        void
) :
    m_display( NULL ),
    m_confirm_button( NULL )
{
}


//-------------------------------------------------------------------------
// See declaration for interface.
//
Display*
KeepKeyBoard::display(
        void
) const
{
    return this->m_display;
}


//-------------------------------------------------------------------------
// See declaration for interface.
//
Button*
KeepKeyBoard::confirm_button(
        void
) const
{
    return this->m_confirm_button;
}


//-------------------------------------------------------------------------
// See declaration for interface.
//
void
KeepKeyBoard::set_display(
        Display* display
)
{
    this->m_display = display;
}


//-------------------------------------------------------------------------
// See declaration for interface.
//
void
KeepKeyBoard::set_confirm_button(
        Button* button
)
{
    this->m_confirm_button = button;
}

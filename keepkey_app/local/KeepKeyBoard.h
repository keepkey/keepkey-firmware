/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file Board.h
///
/// Board interface

#ifndef KeepKeyBoard_H
#define KeepKeyBoard_H


//============================== INCLUDES =================================


#include "Display.h"
#include "Button.h"


//=================== CONSTANTS, MACROS, AND TYPES ========================

//====================== CLASS MEMBER FUNCTIONS ===========================


//-------------------------------------------------------------------------
/// KeepKeyBoard interface class.
///
//-------------------------------------------------------------------------
class KeepKeyBoard
{
public:

    //=============== Public Types and Constants ==========================

    //============== Construction and Destruction =========================


	// Initialize the essentials of the board.
    KeepKeyBoard(
            void
    );


    //================ Public Member Functions ============================


    Display*
    display(
    		void
	) const;


    Button*
    confirm_button(
    		void
	) const;


protected:


	void
	set_display(
			Display* display
	);


	void
	set_confirm_button(
			Button* button
	);

private:


	Display* m_display;


	Button* m_confirm_button;

};


#endif // KeepKeyBoard_H

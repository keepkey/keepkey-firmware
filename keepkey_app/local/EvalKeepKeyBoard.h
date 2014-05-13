/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file Board.h
///
/// Board interface

#ifndef EvalKeepKeyBoard_H
#define EvalKeepKeyBoard_H


//============================== INCLUDES =================================


#include "KeepKeyBoard.h"
#include "STM32F10x.h"
#include "ExternalInterrupt.h"



//=================== CONSTANTS, MACROS, AND TYPES ========================

//====================== CLASS MEMBER FUNCTIONS ===========================


//-------------------------------------------------------------------------
/// Board base class.
///
/// All Board types will extend this.
//-------------------------------------------------------------------------
class EvalKeepKeyBoard
		: public KeepKeyBoard
{
public:

    //=============== Public Types and Constants ==========================


    const STM32F10x::Pins::Id LED_PIN_ID            = STM32F10x::Pins::F_7;
    const STM32F10x::Pins::Id DISPLAY_RESET_PIN_ID  = STM32F10x::Pins::B_7;
    const STM32F10x::Pins::Id DISPLAY_POWER_PIN_ID  = STM32F10x::Pins::B_6;
    const STM32F10x::Pins::Id CONFIRM_BUTTON_PIN_ID = STM32F10x::Pins::G_7;


    //============== Construction and Destruction =========================


	// Initialize the essentials of the board.
    EvalKeepKeyBoard(
            void
    );


    //================ Public Member Functions ============================


    void
    show_led(
    		void
	);


    void
    button_pressed(
            void
    );


protected:

private:

	STM32F10x* mcu;

	Pin* led_pin;
    Pin* confirm_button_pin;

	void
	configure_display(
			void
	);


    void
    configure_button(
            void
    );


    void
    configure_led(
            void
    );

};


#endif // EvalKeepKeyBoard_H

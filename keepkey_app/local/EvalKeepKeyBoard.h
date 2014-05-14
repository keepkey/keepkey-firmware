/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file EvalKeepKeyBoard.h
///
/// Board interface

#ifndef EvalKeepKeyBoard_H
#define EvalKeepKeyBoard_H


//============================== INCLUDES =================================


#include "KeepKeyBoard.h"
#include "hal_stm32f10x_mcu.h"


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


    const Stm32f10x::Mcu::Pins::Id LED_PIN_ID            = Stm32f10x::Mcu::Pins::F_7;
    const Stm32f10x::Mcu::Pins::Id DISPLAY_RESET_PIN_ID  = Stm32f10x::Mcu::Pins::B_7;
    const Stm32f10x::Mcu::Pins::Id DISPLAY_POWER_PIN_ID  = Stm32f10x::Mcu::Pins::B_6;
    const Stm32f10x::Mcu::Pins::Id CONFIRM_BUTTON_PIN_ID = Stm32f10x::Mcu::Pins::G_7;


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

	Stm32f10x::Mcu* mcu;

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

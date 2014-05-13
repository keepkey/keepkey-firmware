/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file EvalKeepKeyBoard.cpp


//=============================== INCLUDES ====================================
    

#include "EvalKeepKeyBoard.h"
#include "KeepKeyDisplay.h"
#include "ExternalInterrupt.h"
#include "STM32F10x.h"
#include "STM32F10x.h"
#include "misc.h"


//=================== CONSTANTS, MACROS, AND TYPES ========================

//============================ VARIABLES ==================================

//====================== CLASSES AND FUNCTIONS ============================


//-------------------------------------------------------------------------
// See declaration for interface.
//
EvalKeepKeyBoard::EvalKeepKeyBoard(
        void
) :
    KeepKeyBoard()
{
    // Initialize the micro
    this->mcu = new STM32F10x();
    this->mcu->initialize();

    // Configure the subsystems.
    this->configure_display();
    this->configure_led();
    this->configure_button();

    this->confirm_button()->set_on_press_handler(
            [ this ](){ this->button_pressed(); }
    );
    
    this->confirm_button()->set_on_release_handler(
            [ this ](){ this->button_pressed(); }
    );
}


//-------------------------------------------------------------------------
// See declaration for interface.
//
void
EvalKeepKeyBoard::button_pressed(
        void
)
{
    this->led_pin->toggle();
}


//-------------------------------------------------------------------------
// See declaration for interface.
//
void
EvalKeepKeyBoard::configure_display(
        void
)
{
    NorSramController* bank4 = this->mcu->get_norsram_bank_4();
    
    // Configure the controller to be correct for the display.
    NorSramController::Config c;
    c.memory_type       = NorSramController::Config::MEMORY_TYPE_SRAM;
    c.memory_data_width = NorSramController::Config::DATA_WIDTH_16B;
    c.write_operation   = NorSramController::Config::WRITE_OPERATION_ENABLE;
    bank4->configure( &c );

    KeepKeyDisplay* display = new KeepKeyDisplay( 
            bank4,
            mcu->get_pin( this->DISPLAY_RESET_PIN_ID ),
            mcu->get_pin( this->DISPLAY_POWER_PIN_ID ) );

    this->set_display( display );
}


//-------------------------------------------------------------------------
// See declaration for interface.
//
void 
EvalKeepKeyBoard::show_led(
        void
) 
{
    this->led_pin->set();
}


//-------------------------------------------------------------------------
// See declaration for interface.
//
void
EvalKeepKeyBoard::configure_led(
        void
)
{
    this->led_pin = this->mcu->get_pin( this->LED_PIN_ID );
    this->led_pin->set_mode( Pin::OUTPUT );
    this->led_pin->enable();
    this->led_pin->reset();
}


//-------------------------------------------------------------------------
// See declaration for interface.
//
void
EvalKeepKeyBoard::configure_button(
        void
)
{
    this->confirm_button_pin = this->mcu->get_pin( this->CONFIRM_BUTTON_PIN_ID );
    this->confirm_button_pin->set_mode( Pin::INPUT );
    this->confirm_button_pin->enable();

    Button* button = new Button( this->confirm_button_pin );
    this->set_confirm_button( button );
}
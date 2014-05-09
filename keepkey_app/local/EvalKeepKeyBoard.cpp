/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file EvalKeepKeyBoard.cpp


//=============================== INCLUDES ====================================
    

#include "EvalKeepKeyBoard.h"
#include "KeepKeyDisplay.h"
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
    //this->configure_interrupts();

    //this->button_press.callback = [ this ](){ this->button_pressed(); };

}


//-------------------------------------------------------------------------
// See declaration for interface.
//
void
EvalKeepKeyBoard::button_pressed(
        void
)
{}


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
EvalKeepKeyBoard::configure_interrupts(
        void
)
{
    // Set the Vector Table base address at 0x08000000
    NVIC_SetVectorTable( NVIC_VectTab_FLASH, 0x00 );

    // Configure the Priority Group to 2 bits
    NVIC_PriorityGroupConfig( NVIC_PriorityGroup_2 );
}
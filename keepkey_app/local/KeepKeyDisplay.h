/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file KeepKeyDisplay.h
///
/// Base class for displays which defines a common public interface.

#ifndef KeepKeyDisplay_H
#define KeepKeyDisplay_H


//================================ INCLUDES ===================================


#include "Display.h"
#include "MemoryController.h"
#include "Pin.h"


//=================== CONSTANTS, MACROS, AND TYPES ========================


// Break if an architecture isn't supported.
#if !defined(STM32F10X_HD)
#   error "Unsupported architecture for this display"
#endif


#define KEEPKEY_DISPLAY_WIDTH   256
#define KEEPKEY_DISPLAY_HEIGHT  64


//====================== CLASS MEMBER FUNCTIONS ===========================


//-------------------------------------------------------------------------
/// Display base class.
///
/// Provide basic functions for writing a frame buffer to a display.
//-------------------------------------------------------------------------
class KeepKeyDisplay
    : public Display
{
public:

    //=============== Public Types and Constants ==========================


    static const uint32_t ADDRESS_SETUP_TIME    = 10;
    static const uint32_t ADDRESS_HOLD_TIME     = 0;
    static const uint32_t DATA_SETUP_TIME       = 40;
    static const uint32_t BUS_TURNAROUND_DURATION = 10;
    static const uint32_t DATA_LATENCY          = 7;


    //============== Construction and Destruction =========================

    
    KeepKeyDisplay(
            MemoryController* controller,
            Pin* reset_pin,
            Pin* power_pin
    );


    //================ Public Member Functions ============================


    /// Turn off the display
    void
    turn_off( 
            void
    );

    
    /// Turn on the display
    void
    turn_on(
            void
    );


    void
    clear(
            void
    );


    void
    set_brightness(
            int percentage_on
    );


protected:

    /// Draw a frame to the display.
    void 
    on_refresh( 
            void
    );


private:


    uint32_t reg_address;
    uint32_t ram_address;


    // Hardware interfaces
    MemoryController* m_mem;
    Pin* m_reset_pin;
    Pin* m_power_pin;


    void
    initialize(
            void
    );


    void
    write_reg(
            uint8_t reg,
            uint8_t value
    );


    void
    write_reg(
            uint8_t reg,
            uint8_t* values,
            int length
    );

    
    void
    write_display_data_prepare(
            void
    );


    void
    delay(
            int ms
    );


    void
    write_display_data(
            uint32_t image,
            uint16_t height,
            uint16_t width,
            uint16_t x,
            uint16_t y
    );


    void
    write_display_data(
            uint32_t image,
            uint16_t height,
            uint16_t width
    );


    void
    set_window(
            uint16_t height,
            uint16_t width,
            uint16_t x,
            uint16_t y
    );


};


#endif // KeepKeyDisplay_H

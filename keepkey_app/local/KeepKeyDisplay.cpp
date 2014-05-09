/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file KeepKeyDisplayl.cpp


//=============================== INCLUDES ====================================


#include "KeepKeyDisplay.h"
#include "Pixel.h"

#if !defined(USING_HAL)
#include "stm32f10x_gpio.h"
#include "stm32f10x_rcc.h"
#include "stm32f10x_fsmc.h"
#endif
    

//=================== CONSTANTS, MACROS, AND TYPES ========================


#define START_COL ((uint8_t)0x1C)
#define START_ROW ((uint8_t)0x00)



//============================ VARIABLES ==================================

//====================== CLASSES AND FUNCTIONS ============================


//-------------------------------------------------------------------------
// See declaration for interface.
//
KeepKeyDisplay::KeepKeyDisplay(
        MemoryController* controller,
        Pin* reset_pin,
        Pin* power_pin
) :
        Display( Pixel::A4, KEEPKEY_DISPLAY_HEIGHT, KEEPKEY_DISPLAY_WIDTH ),
        m_mem( controller ),
        m_reset_pin( reset_pin ),
        m_power_pin( power_pin )
{
    MemoryController::Timing t;
    t.address_setup_time_ns     = KeepKeyDisplay::ADDRESS_SETUP_TIME;
    t.address_hold_time_ns      = KeepKeyDisplay::ADDRESS_HOLD_TIME;
    t.data_setup_time_ns        = KeepKeyDisplay::DATA_SETUP_TIME;
    t.bus_turnaround_duration_ns = KeepKeyDisplay::BUS_TURNAROUND_DURATION;
    t.data_latency_ns           = KeepKeyDisplay::DATA_LATENCY;

    controller->set_timing( &t );
    controller->enable();

    this->m_reset_pin->set_mode( Pin::OPEN_DRAIN );
    this->m_reset_pin->enable();

    this->m_power_pin->set_mode( Pin::OPEN_DRAIN );
    this->m_power_pin->enable();    

    this->initialize();
}


//-------------------------------------------------------------------------
// See declaration for interface.
//
void 
KeepKeyDisplay::on_refresh( 
        void
)
{
    this->set_window( this->height(), this->width(), 0, 0 );

    this->write_display_data_prepare();

    // The endpoint is 1/2 x*y because each write outputs 2 pixels.
    int end = ( this->height() * this->width() ) / 2;
    int i;
    uint8_t* data = (uint8_t*)this->frame_buffer()->origin();
    for( i = 0; i < end; i++ )
    {
    	uint8_t data_to_write = data[ i ];
        this->m_mem->write( this->ram_address, data_to_write );
        //*this->ram_address = data_to_write;
    }
}


//-------------------------------------------------------------------------
// See declaration for interface.
//
void
KeepKeyDisplay::turn_off( 
        void
)
{
    this->m_mem->write( this->reg_address, (uint8_t)0xAE );
}


//-------------------------------------------------------------------------
// See declaration for interface.
//
void
KeepKeyDisplay::turn_on(
        void
)
{
    this->m_mem->write( this->reg_address, (uint8_t)0xAF );
}


//-------------------------------------------------------------------------
// See declaration for interface.
//
void
KeepKeyDisplay::set_brightness(
        int v
)
{
    // Clip to be 0 <= value <= 100
    v = ( v >= 0 ) ? v : 0;
    v = ( v > 100 ) ? 100 : v;

    v = ( 0xFF * v ) / 100;

    uint8_t reg_value = (uint8_t)v;

    this->m_mem->write( this->reg_address, (uint8_t)0xC1 );
    this->m_mem->write( this->ram_address, reg_value );
}


//-------------------------------------------------------------------------
// See declaration for interface.
// 
void
KeepKeyDisplay::initialize(
        void
)
{
    KeepKeyDisplay::delay( 5 );

    this->m_power_pin->reset();

    this->m_reset_pin->reset();
    KeepKeyDisplay::delay( 1 );
    this->m_reset_pin->set();

    KeepKeyDisplay::delay( 5 );

    // Registers to write to.
    this->reg_address = this->m_mem->start_addr();
    this->ram_address = this->reg_address + 2;

    this->m_mem->write( this->reg_address, (uint8_t)0xFD ); 
    this->m_mem->write( this->ram_address, (uint8_t)0x12 ); 

    this->turn_off();

    // Divide DIVSET by 2?
    this->m_mem->write( this->reg_address, (uint8_t)0xB3 ); 
    this->m_mem->write( this->ram_address, (uint8_t)0x91 ); 

    this->m_mem->write( this->reg_address, (uint8_t)0xCA ); 
    this->m_mem->write( this->ram_address, (uint8_t)0x3F ); 

    this->m_mem->write( this->reg_address, (uint8_t)0xA2 ); 
    this->m_mem->write( this->ram_address, (uint8_t)0x00 ); 

    this->m_mem->write( this->reg_address, (uint8_t)0xA1 ); 
    this->m_mem->write( this->ram_address, (uint8_t)0x00 ); 

    this->set_window( 
            (uint8_t)this->height(),
            (uint8_t)this->width(),
            0,
            0
    );

    // Horizontal address increment
    // Disable colum address re-map
    // Disable nibble re-map
    // Scan from COM0 to COM[n-1]
    // Disable dual COM mode
    this->m_mem->write( this->reg_address, (uint8_t)0xA0 ); 
    //this->m_mem->write( this->ram_address, (uint8_t)0x00;
    //this->m_mem->write( this->ram_address, (uint8_t)0x01;
    this->m_mem->write( this->ram_address, (uint8_t)0x14 ); 
    this->m_mem->write( this->ram_address, (uint8_t)0x11 ); 

    // GPIO0: pin HiZ, Input disabled
    // GPIO1: pin HiZ, Input disabled
    this->m_mem->write( this->reg_address, (uint8_t)0xB5 ); 
    this->m_mem->write( this->ram_address, (uint8_t)0x00 ); 

    // Enable internal Vdd regulator?
    this->m_mem->write( this->reg_address, (uint8_t)0xAB ); 
    this->m_mem->write( this->ram_address, (uint8_t)0x01 ); 

    // 
    this->m_mem->write( this->reg_address, (uint8_t)0xB4 ); 
    this->m_mem->write( this->ram_address, (uint8_t)0xA0 ); 
    this->m_mem->write( this->ram_address, (uint8_t)0xFD ); 

    this->set_brightness( 65 ); 

    this->m_mem->write( this->reg_address, (uint8_t)0xC7 ); 
    this->m_mem->write( this->ram_address, (uint8_t)0x0F ); 

    this->m_mem->write( this->reg_address, (uint8_t)0xB9 ); 

    this->m_mem->write( this->reg_address, (uint8_t)0xB1 ); 
    this->m_mem->write( this->ram_address, (uint8_t)0xE2 ); 

    this->m_mem->write( this->reg_address, (uint8_t)0xD1 ); 
    this->m_mem->write( this->ram_address, (uint8_t)0x82 ); 
    this->m_mem->write( this->ram_address, (uint8_t)0x20 ); 

    this->m_mem->write( this->reg_address, (uint8_t)0xBB ); 
    this->m_mem->write( this->ram_address, (uint8_t)0x1F ); 

    this->m_mem->write( this->reg_address, (uint8_t)0xB6 ); 
    this->m_mem->write( this->ram_address, (uint8_t)0x08 ); 

    this->m_mem->write( this->reg_address, (uint8_t)0xBE ); 
    this->m_mem->write( this->ram_address, (uint8_t)0x07 ); 

    this->m_mem->write( this->reg_address, (uint8_t)0xA6 ); 

    KeepKeyDisplay::delay( 1 );

    this->clear();

    // Turn on 12V
    this->m_power_pin->set();

    KeepKeyDisplay::delay( 10 );

    this->turn_on();
}


//-------------------------------------------------------------------------
// See declaration for interface.
// 
void
KeepKeyDisplay::write_reg(
        uint8_t reg,
        uint8_t value
)
{
    this->m_mem->write( this->reg_address, reg );
    this->m_mem->write( this->ram_address, value );
}


//-------------------------------------------------------------------------
// See declaration for interface.
// 
void
KeepKeyDisplay::write_reg(
        uint8_t reg,
        uint8_t* values,
        int num
)
{
    this->m_mem->write( this->reg_address, reg );

    int i;
    for( i = 0; i < num; i++ )
    {
        this->m_mem->write( this->ram_address, values[ i ] );
    }
}


//-------------------------------------------------------------------------
// See declaration for interface.
// 
void
KeepKeyDisplay::clear(
        void
)
{
    this->set_window( (uint8_t)this->height(), (uint8_t)this->width(), 0, 0 );

    // Set the screen to display-writing mode
    this->write_display_data_prepare();

    KeepKeyDisplay::delay( 1 );

    // Make the display blank
    int end = this->height() * this->width();
    int i;
    for( i = 0; i < end; i += 2 )
    {
        this->m_mem->write( this->ram_address, (uint8_t)0x00 );
    }
}


//-------------------------------------------------------------------------
// See declaration for interface.
// 
void
KeepKeyDisplay::write_display_data_prepare(
        void
)
{
    this->m_mem->write( this->reg_address, (uint8_t)0x5C );
}


//-------------------------------------------------------------------------
// See declaration for interface.
// 
void
KeepKeyDisplay::write_display_data(
        uint32_t image,
        uint16_t height,
        uint16_t width
)
{
    this->write_display_data( image, height, width, 0, 0 );
}


//-------------------------------------------------------------------------
// See declaration for interface.
// 
void
KeepKeyDisplay::write_display_data(
        uint32_t image,
        uint16_t height,
        uint16_t width,
        uint16_t x,
        uint16_t y
)
{
    this->set_window( height, width, x, y );
    this->write_display_data_prepare();
    KeepKeyDisplay::delay( 1 );

    int length = height * width;

    uint8_t* data = (uint8_t*)image;
    int i;
    for( i = 0; i < length; i += 2 )
    {
        uint8_t v = ( data[ i ] & (uint8_t)0xF0 ) | ( ( data[ i + 1 ] >> 4 ) & (uint8_t)0x0F );
        this->m_mem->write( this->ram_address, v );
    }
}


//-------------------------------------------------------------------------
// See declaration for interface.
// 
void
KeepKeyDisplay::set_window(
        uint16_t height,
        uint16_t width,
        uint16_t x,
        uint16_t y
)
{
    /// @TODO (PB) Check that the window is in bounds.

    uint8_t row_start = START_ROW + y;
    uint8_t row_end = row_start + height - 1;

    // Width is in units of 4 pixels/column (2 bytes at 4 bits/pixel)
    width /= 4;
    x /= 4;
    uint8_t col_start = START_COL + x;
    uint8_t col_end = col_start + width - 1;

    this->m_mem->write( this->reg_address, (uint8_t)0x75 );
    this->m_mem->write( this->ram_address, row_start );
    this->m_mem->write( this->ram_address, row_end );
    this->m_mem->write( this->reg_address, (uint8_t)0x15 );
    this->m_mem->write( this->ram_address, col_start );
    this->m_mem->write( this->ram_address, col_end );

/*
    // Set row start and end address
    *this->reg_address = (uint8_t)0x75;
    *this->ram_address = row_start;
    *this->ram_address = row_end;

    // Set column start and end address
    *this->reg_address = (uint8_t)0x15;
    *this->ram_address = col_start;
    *this->ram_address = col_end;
    */
}


//-------------------------------------------------------------------------
// See declaration for interface.
// 
void
KeepKeyDisplay::delay(
        int ms
)
{
    volatile uint32_t index = 0; 
    for( index = (100000 * ms); index != 0; index-- )
    {}
}


#if 0
//-------------------------------------------------------------------------
// See declaration for interface.
// 
void
KeepKeyDisplay::initialize_hal(
        void
)
{

    GPIO_InitTypeDef gpio_init;

    // Enable FSMC, GPIOD, GPIOE, GPIOF, GPIOG and AFIO clocks
    RCC_AHBPeriphClockCmd( RCC_AHBPeriph_FSMC, ENABLE );
    RCC_APB2PeriphClockCmd(
            RCC_APB2Periph_GPIOD | 
            RCC_APB2Periph_GPIOE |  
            RCC_APB2Periph_GPIOF | 
            RCC_APB2Periph_GPIOG |
            RCC_APB2Periph_AFIO, 
            ENABLE
    );

    // Set PD.00(D2), PD.01(D3), PD.04(NOE), PD.05(NWE), PD.08(D13), PD.09(D14),
    // PD.10(D15), PD.14(D0), PD.15(D1) as alternate function push pull
    gpio_init.GPIO_Pin = 
            GPIO_Pin_0 | 
            GPIO_Pin_1 | 
            GPIO_Pin_4 | 
            GPIO_Pin_5 |
            GPIO_Pin_8 | 
            GPIO_Pin_9 | 
            GPIO_Pin_10 | 
            GPIO_Pin_14 |
            GPIO_Pin_15;
    gpio_init.GPIO_Speed = GPIO_Speed_50MHz;
    gpio_init.GPIO_Mode = GPIO_Mode_AF_PP;
    GPIO_Init( GPIOD, &gpio_init );

    // Set PE.07(D4), PE.08(D5), PE.09(D6), PE.10(D7), PE.11(D8), PE.12(D9), PE.13(D10),
    // PE.14(D11), PE.15(D12) as alternate function push pull
    gpio_init.GPIO_Pin = 
            GPIO_Pin_7 | 
            GPIO_Pin_8 |     
            GPIO_Pin_9 | 
            GPIO_Pin_10 |    
            GPIO_Pin_11 |  
            GPIO_Pin_12 | 
            GPIO_Pin_13 | 
            GPIO_Pin_14 |    
            GPIO_Pin_15;
    GPIO_Init( GPIOE, &gpio_init );

    // Set PF.00(A0 (RS)) as alternate function push pull
    gpio_init.GPIO_Pin = GPIO_Pin_0;
    GPIO_Init( GPIOF, &gpio_init );

    // Set PG.12(NE4 (LCD/CS)) as alternate function push pull - CE3(LCD /CS)
    gpio_init.GPIO_Pin = GPIO_Pin_12;
    GPIO_Init( GPIOG, &gpio_init );

    FSMC_NORSRAMInitTypeDef fsmc_init;
    FSMC_NORSRAMTimingInitTypeDef  p;

    // FSMC Configuration for SRAM Bank 4, FSMC_Bank1_NORSRAM4 
    p.FSMC_AddressSetupTime         = 1;
    p.FSMC_AddressHoldTime          = 1;
    p.FSMC_DataSetupTime            = 4;
    p.FSMC_BusTurnAroundDuration    = 1;
    p.FSMC_CLKDivision              = 0;
    p.FSMC_DataLatency              = 1;
    p.FSMC_AccessMode               = FSMC_AccessMode_A;

    // Bank configuration
    // LCD configured as follow:
    //      - Data/Address MUX = Disable
    //      - Memory Type = SRAM
    //      - Data Width = 16bit
    //      - Write Operation = Enable
    //      - Extended Mode = Enable
    //      - Asynchronous Wait = Disable
    fsmc_init.FSMC_Bank                 = FSMC_Bank1_NORSRAM4;
    fsmc_init.FSMC_DataAddressMux       = FSMC_DataAddressMux_Disable;
    fsmc_init.FSMC_MemoryType           = FSMC_MemoryType_SRAM;
    fsmc_init.FSMC_MemoryDataWidth      = FSMC_MemoryDataWidth_16b;
    fsmc_init.FSMC_BurstAccessMode      = FSMC_BurstAccessMode_Disable;
    fsmc_init.FSMC_AsynchronousWait     = FSMC_AsynchronousWait_Disable;  
    fsmc_init.FSMC_WaitSignalPolarity   = FSMC_WaitSignalPolarity_Low;
    fsmc_init.FSMC_WrapMode             = FSMC_WrapMode_Disable;
    fsmc_init.FSMC_WaitSignalActive     = FSMC_WaitSignalActive_BeforeWaitState;
    fsmc_init.FSMC_WriteOperation       = FSMC_WriteOperation_Enable;
    fsmc_init.FSMC_WaitSignal           = FSMC_WaitSignal_Disable;
    fsmc_init.FSMC_ExtendedMode         = FSMC_ExtendedMode_Disable;
    fsmc_init.FSMC_WriteBurst           = FSMC_WriteBurst_Disable;
    fsmc_init.FSMC_ReadWriteTimingStruct = &p;
    fsmc_init.FSMC_WriteTimingStruct    = &p;

    FSMC_NORSRAMInit( &fsmc_init );

    // BANK 4 (of NOR/SRAM Bank 1~4) is enabled
    FSMC_NORSRAMCmd( FSMC_Bank1_NORSRAM4, ENABLE );
}
#endif

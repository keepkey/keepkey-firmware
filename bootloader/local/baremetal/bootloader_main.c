/* START KEEPKEY LICENSE */
/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2014 KeepKey LLC
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/* END KEEPKEY LICENSE */

//================================ INCLUDES =================================== 
//
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/spi.h>
#include <libopencm3/stm32/f2/rng.h>


#include <memory.h>
#include <keepkey_board.h>
#include <keepkey_display.h>
#include <keepkey_leds.h>
#include <keepkey_button.h>
#include <keepkey_usart.h>
#include <timer.h>
#include <layout.h>

#include <confirm_sm.h>
#include <usb_driver.h>
#include <usb_flash.h>
#include <ecdsa.h>
#include <bootloader.h>


//====================== CONSTANTS, TYPES, AND MACROS =========================

typedef void (*app_entry_t)(void);

//=============================== VARIABLES ===================================

uint32_t * const  SCB_VTOR = (uint32_t*)0xe000ed08;


static const uint8_t pubkey[PUBKEYS][PUBKEY_LENGTH] = 
{
    {
	  /*"\x04\x49\x61\x2a\xa7\x12\x4c\xb1\x50\x29\x62\x2b\x67\xf2\x7e\x7f\xa7\xbf\x41\x2f\xc6\xa7\x44\x80\xe1\x79\x20\x9a\xb2\xfc\x9b\x6b\x5b\xd3\x74\xfa\x2a\x55\x59\x86\x14\x5c\x5e\x8b\x53\xc3\x20\x94\x54\x15\x80\xea\x83\x21\x52\x1c\x63\xae\x20\x82\xe8\x9a\xb7\xec\x64"*/
	  0x04, 0x49, 0x61, 0x2a, 0xa7, 0x12, 0x4c, 0xb1, 0x50, 0x29, 0x62, 0x2b, 0x67, 0xf2, 0x7e, 0x7f, 0xa7, 0xbf, 0x41, 0x2f, 
      0xc6, 0xa7, 0x44, 0x80, 0xe1, 0x79, 0x20, 0x9a, 0xb2, 0xfc, 0x9b, 0x6b, 0x5b, 0xd3, 0x74, 0xfa, 0x2a, 0x55, 0x59, 0x86, 
      0x14, 0x5c, 0x5e, 0x8b, 0x53, 0xc3, 0x20, 0x94, 0x54, 0x15, 0x80, 0xea, 0x83, 0x21, 0x52, 0x1c, 0x63, 0xae, 0x20, 0x82, 
      0xe8, 0x9a, 0xb7, 0xec, 0x64
    }, 

    {
    /*\x04\xff\x88\x77\x68\xc9\x56\x5c\xc6\x30\xc8\xf0\x13\x96\xdd\x2b\x0b\xf5\x20\x91\x3f\x53\xf2\xf3\x1e\x4f\xe9\x21\x81\xc6\xca\x44\xca\xd3\xb6\xe6\xde\x69\x12\x96\x3c\x05\x63\x1a\xe6\xcc\xe7\xdc\x8c\xa7\x21\x11\xd3\xc8\x26\x37\x3d\x10\x4e\xc2\x91\x85\x51\x8d\x29"*/
      0x04, 0xff, 0x88, 0x77, 0x68, 0xc9, 0x56, 0x5c, 0xc6, 0x30, 0xc8, 0xf0, 0x13, 0x96, 0xdd, 0x2b, 0x0b, 0xf5, 0x20, 0x91, 
      0x3f, 0x53, 0xf2, 0xf3, 0x1e, 0x4f, 0xe9, 0x21, 0x81, 0xc6, 0xca, 0x44, 0xca, 0xd3, 0xb6, 0xe6, 0xde, 0x69, 0x12, 0x96, 
      0x3c, 0x05, 0x63, 0x1a, 0xe6, 0xcc, 0xe7, 0xdc, 0x8c, 0xa7, 0x21, 0x11, 0xd3, 0xc8, 0x26, 0x37, 0x3d, 0x10, 0x4e, 0xc2, 
      0x91, 0x85, 0x51, 0x8d, 0x29
    },
    {
	/*\x04\x31\x65\xfc\x84\x07\x40\xf8\xd8\xdb\x33\xa5\x54\x4f\x23\xcf\x63\xd1\x3a\xcb\xb9\x54\x82\xcd\x7a\x7c\xc5\x5f\x2b\xfa\x38\x3a\x9d\x5a\x7f\xf7\x2a\xad\xd9\x1b\x98\x1a\x6c\xc6\x83\xd3\x1a\x14\xd9\x1f\x35\x33\xd3\xf0\xb2\x04\x44\x66\x67\x90\x72\x99\x0a\x44\x24"*/
	  0x04, 0x31, 0x65, 0xfc, 0x84, 0x07, 0x40, 0xf8, 0xd8, 0xdb, 0x33, 0xa5, 0x54, 0x4f, 0x23, 0xcf, 0x63, 0xd1, 0x3a, 0xcb, 
      0xb9, 0x54, 0x82, 0xcd, 0x7a, 0x7c, 0xc5, 0x5f, 0x2b, 0xfa, 0x38, 0x3a, 0x9d, 0x5a, 0x7f, 0xf7, 0x2a, 0xad, 0xd9, 0x1b, 
      0x98, 0x1a, 0x6c, 0xc6, 0x83, 0xd3, 0x1a, 0x14, 0xd9, 0x1f, 0x35, 0x33, 0xd3, 0xf0, 0xb2, 0x04, 0x44, 0x66, 0x67, 0x90, 
      0x72, 0x99, 0x0a, 0x44, 0x24
    },
    {
	/*"\x04\x72\x3d\xbd\x89\x80\xc2\x24\x07\x36\x03\xc7\x0e\x99\xe1\xb3\xc9\x83\xa2\x5d\xc0\x39\x59\x42\x65\xfd\x13\x30\x2a\xf9\x87\x2a\x3a\xcd\x16\x20\xc3\x01\x00\x46\xb4\xbc\x80\x6d\x9f\x9f\x96\x00\x89\x9c\xf0\xd5\x70\xed\xc2\xec\x04\x34\x71\x54\x4f\xf6\x7c\xcb\x6d"*/
	  0x04, 0x72, 0x3d, 0xbd, 0x89, 0x80, 0xc2, 0x24, 0x07, 0x36, 0x03, 0xc7, 0x0e, 0x99, 0xe1, 0xb3, 0xc9, 0x83, 0xa2, 0x5d, 
      0xc0, 0x39, 0x59, 0x42, 0x65, 0xfd, 0x13, 0x30, 0x2a, 0xf9, 0x87, 0x2a, 0x3a, 0xcd, 0x16, 0x20, 0xc3, 0x01, 0x00, 0x46, 
      0xb4, 0xbc, 0x80, 0x6d, 0x9f, 0x9f, 0x96, 0x00, 0x89, 0x9c, 0xf0, 0xd5, 0x70, 0xed, 0xc2, 0xec, 0x04, 0x34, 0x71, 0x54, 
      0x4f, 0xf6, 0x7c, 0xcb, 0x6d
    },
    {
	/*(uint8_t *)"\x04\xc5\xb6\x2a\x94\xf2\xdb\xd7\x49\x78\xd5\x49\x90\xda\xc9\xb8\xf4\xaa\x48\x61\x96\x97\x45\xf1\x32\x8f\x19\x6c\x38\xa2\x43\x5c\xe5\x95\xaa\x14\xc2\x0c\x44\x88\x9d\x24\x80\x92\x93\x54\x04\xad\x84\xc6\xa4\xcc\x39\x7d\x06\x36\xbe\x0e\x0f\xd6\x5a\xf5\xcc\x75\x08"*/
	  0x04, 0xc5, 0xb6, 0x2a, 0x94, 0xf2, 0xdb, 0xd7, 0x49, 0x78, 0xd5, 0x49, 0x90, 0xda, 0xc9, 0xb8, 0xf4, 0xaa, 0x48, 0x61, 
      0x96, 0x97, 0x45, 0xf1, 0x32, 0x8f, 0x19, 0x6c, 0x38, 0xa2, 0x43, 0x5c, 0xe5, 0x95, 0xaa, 0x14, 0xc2, 0x0c, 0x44, 0x88, 
      0x9d, 0x24, 0x80, 0x92, 0x93, 0x54, 0x04, 0xad, 0x84, 0xc6, 0xa4, 0xcc, 0x39, 0x7d, 0x06, 0x36, 0xbe, 0x0e, 0x0f, 0xd6, 
      0x5a, 0xf5, 0xcc, 0x75, 0x08
    }
};

//====================== PRIVATE FUNCTION DECLARATIONS ========================


//=============================== FUNCTIONS ===================================

static bool validate_firmware()
{
    return true;
}

/**
 * Lightweight routine to reset the vector table to point to the application's vector table.
 *
 * @param offset This must be a multiple of 0x200.  This is added to to the base address of flash
 *               in order to compute the correct base address.
 * 
 */
static void set_vector_table_offset(uint32_t offset)
{ 
    static const uint32_t NVIC_OFFSET_FLASH = ((uint32_t)0x08000000);

    *SCB_VTOR = NVIC_OFFSET_FLASH | (offset & (uint32_t)0x1FFFFF80);
}

static void boot_jump(uint32_t addr)
{
    /*
     * Jump to one after the base app address to get past the stack pointer.  The +1 
     * is to maintain a valid thumb instruction.
     */
    uint32_t entry_addr = addr+4;
    uint32_t app_entry_addr = (uint32_t)(*(uint32_t*)(entry_addr));
    app_entry_t app_entry = (app_entry_t)app_entry_addr;
    app_entry();
}

void blink(void* context)
{
    toggle_red();    
}



static void configure_hw()
{
    clock_scale_t clock = hse_8mhz_3v3[CLOCK_3V3_120MHZ];
    rcc_clock_setup_hse_3v3(&clock);

    rcc_periph_clock_enable(RCC_GPIOA);
    rcc_periph_clock_enable(RCC_GPIOB);
    rcc_periph_clock_enable(RCC_GPIOC);
    rcc_periph_clock_enable(RCC_OTGFS);
    rcc_periph_clock_enable(RCC_SYSCFG);
    rcc_periph_clock_enable(RCC_TIM4);

    timer_init();

    usart_init();

    keepkey_leds_init();

    keepkey_button_init();

    display_init();
    layout_init( display_canvas() );
}

/**************************************************************************
 *  check_firmware_gig() - check image application partition is the 
 *                         valid keepkey firmware
 *  INPUT 
 *      - none
 *  OUTPUT
 *      - true/false
 *
 * ***********************************************************************/
bool check_firmware_sig(void)
{
	uint32_t index;
    uint8_t (*app_meta_sig_ptr)[64] = (uint8_t (*)[])FLASH_META_SIG1;
	bool retval = false;
    app_meta_td *app_meta = (app_meta_td *)FLASH_META_START;         

	/* ensure all 3 signatures are not from duplicate private keys */
    if( (app_meta->sig_index1 != app_meta->sig_index2) && 
        (app_meta->sig_index1 != app_meta->sig_index3) && 
        (app_meta->sig_index2 != app_meta->sig_index3))
    {
        /* ensure all indexes are 0 - 4 */
        if((app_meta->sig_index1 < PUBKEYS) && (app_meta->sig_index2 <PUBKEYS) && (app_meta->sig_index3 < PUBKEYS))
        {
            for(index = 0; index < SIGNATURES; index++)
            {
                dbg_print("sigPtr 0x%x\n\r", app_meta_sig_ptr[index]);
	            if (ecdsa_verify(&pubkey[index][0], (uint8_t *)app_meta_sig_ptr[index], (uint8_t *)FLASH_APP_START, app_meta->code_len ))
                {
                    break;
                }
                else
                {
                    /* verify this pass run is from the last signature */ 
                    if(index == SIGNATURES-1)
                    {
                        retval = true;
                    }
                    dbg_print("sign %d OK, %d\n\r", index, retval);
                }
            }
        }
    }
	return(retval);
}

const char* firmware_sig_as_string(void)
{
    return "NOSIG";
}

void board_reset(void)
{
    scb_reset_system();
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    configure_hw();

    bool update_mode = keepkey_button_down();

    set_green();
    set_red();

    dbg_print("\n\rKeepKey LLC, Copyright (C) 2014\n\r");
    dbg_print("BootLoader Version %d.%d (%s)\n\r", BOOTLOADER_MAJOR_VERSION, BOOTLOADER_MINOR_VERSION, __DATE__);


    while(1)
    {
        if(validate_firmware() && !update_mode)
        {
            if(!check_firmware_sig())
            {
                /* KeepKey signature check failed.  Foreign code might be sitting there. Take action to clear storage partition!!! */
                layout_standard_notification("UNSIGNED FIRMWARE", firmware_sig_as_string(), NOTIFICATION_INFO);
                display_refresh();
                delay(5000);
            }

            clear_red();
            set_vector_table_offset(FLASH_APP_START - FLASH_ORIGIN);  //offset = 0x60100
            boot_jump(FLASH_APP_START);
        } else {
            clear_green();

            if(usb_flash_firmware())
            {
                layout_standard_notification("Firmware Update Complete", "Please disconnect and reconnect your KeepKey to continue.", NOTIFICATION_UNPLUG);
                display_refresh();
            } 
            else 
            {
                layout_standard_notification("Invalid firmware image detected.", "Reset and perform a firmware update.", NOTIFICATION_INFO);
                display_refresh();
            }
            break;  /* break out of this loop and hang out in infinite loop */
        }
    }

    while(1) {}

    return(0);
}

/* START KEEPKEY LICENSE */
/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2015 KeepKey LLC
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
#include <string.h>

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/spi.h>
#include <libopencm3/stm32/f2/rng.h>
#include <libopencm3/cm3/cortex.h>

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
#include <rng.h>



//=============================== VARIABLES ===================================

uint32_t * const  SCB_VTOR = (uint32_t*)0xe000ed08;

static const uint8_t pubkey[PUBKEYS][PUBKEY_LENGTH] = 
{
    {
        /* Public key 1 */
        0x04, 0x3d, 0xf3, 0x3e, 0xf8, 0x11, 0xa8, 0x4f, 0xf7, 0x17, 0xf2, 0x06, 0xee, 0x50, 0x85, 0x23, 0xb5, 0x07, 0xa5, 0x1a,
        0xcc, 0x7a, 0x83, 0xd1, 0xc7, 0x8d, 0x9f, 0x59, 0x92, 0x98, 0xa2, 0xa6, 0x0a, 0x7c, 0x4a, 0xb1, 0x44, 0x24, 0x79, 0x1e,
        0xdd, 0xbc, 0x47, 0xe1, 0x59, 0xe4, 0x2f, 0xcf, 0x3d, 0x2a, 0xe3, 0x5e, 0x18, 0x5e, 0x8d, 0x3d, 0x7a, 0x39, 0x35, 0x3d,
        0x51, 0x2d, 0x86, 0xb5, 0xa9
    }, 

    {
        /* Public key 2 */
        0x04, 0x46, 0x53, 0xd2, 0xf7, 0x36, 0xff, 0x71, 0xff, 0x1c, 0x81, 0xc0, 0x77, 0x1c, 0x1d, 0x5f, 0xd4, 0xf9, 0x11, 0x83,
        0x19, 0x81, 0x0d, 0xdf, 0xbe, 0x2d, 0xf6, 0xa0, 0x6e, 0x2a, 0x3f, 0x1c, 0x9f, 0x0d, 0x58, 0x23, 0x79, 0xfc, 0x92, 0x21,
        0x7f, 0x9e, 0x4b, 0x02, 0x08, 0x32, 0x4f, 0x8f, 0xea, 0x7c, 0x51, 0x58, 0xe6, 0xf5, 0x7d, 0x9c, 0x32, 0x52, 0x97, 0xdf,
        0x42, 0xbc, 0xd9, 0x94, 0x8e
    },

    {
        /* Public key 3 */
        0x04, 0x7d, 0x6f, 0x93, 0xc1, 0x44, 0x10, 0x6b, 0x89, 0x80, 0x4f, 0x9c, 0xdb, 0x52, 0xc5, 0xbe, 0x64, 0x94, 0xd9, 0x5c,
        0xda, 0x57, 0x13, 0x9f, 0xfa, 0x78, 0xbc, 0xe2, 0x97, 0xb1, 0x11, 0x61, 0xa8, 0x27, 0x16, 0xdf, 0x9f, 0x71, 0x88, 0xbe,
        0xda, 0xbf, 0x80, 0xf9, 0x16, 0xcc, 0x59, 0xd2, 0x0d, 0xe4, 0x16, 0x63, 0x43, 0xc0, 0x31, 0xaf, 0x73, 0x68, 0x39, 0x11,
        0x79, 0x3c, 0xb4, 0xcf, 0x6c
    },

    {
        /* Public key 4 */
        0x04, 0xbe, 0x4b, 0x4c, 0xe2, 0xec, 0x27, 0x8c, 0xda, 0xa2, 0xfa, 0xe0, 0xd2, 0x84, 0xd8, 0x58, 0x1c, 0xda, 0x0b, 0xcf,
        0x1b, 0x0d, 0x30, 0x19, 0x29, 0x81, 0xfc, 0xea, 0x77, 0x27, 0x5b, 0xf2, 0xb2, 0xd0, 0xb1, 0x36, 0x7b, 0x41, 0x89, 0x9e,
        0x82, 0x97, 0x70, 0x29, 0x10, 0x3f, 0xc0, 0xf5, 0x97, 0x56, 0x59, 0xb6, 0x26, 0x41, 0x54, 0x8b, 0xf5, 0x67, 0xea, 0x57,
        0x8d, 0x89, 0x1a, 0x05, 0x6d
    },

    {
        /* Public key 5 */
        0x04, 0xef, 0xd0, 0x1d, 0x54, 0x3f, 0x85, 0xeb, 0xc1, 0x38, 0x2a, 0xfd, 0xc1, 0x2a, 0x24, 0x60, 0x8e, 0xe6, 0xc4, 0xa1,
        0x34, 0xf9, 0xad, 0xb4, 0x8b, 0x9b, 0xe5, 0x7e, 0x6e, 0x04, 0x15, 0x07, 0xa6, 0xd8, 0x83, 0xcd, 0x79, 0x6c, 0xb1, 0xe8,
        0xcc, 0xed, 0x77, 0x0b, 0xe5, 0xfe, 0x4f, 0x61, 0x4e, 0x0d, 0xe8, 0x94, 0xd8, 0x26, 0xe2, 0xb3, 0x81, 0x03, 0x53, 0xca,
        0xc3, 0x38, 0x81, 0x59, 0xf3
    }
};

//====================== PRIVATE FUNCTION DECLARATIONS ========================


//=============================== FUNCTIONS ===================================

/*
 * system_halt() - forever loop here
 *
 * INPUT - none
 * OUTPUT - none
 */
void __attribute__((noreturn)) system_halt(void)
{
    /*disable interrupts */
	cm_disable_interrupts();
    for (;;) {} // loop forever
}

/*
 * Lightweight routine to reset the vector table to point to the application's vector table.
 *
 * @param offset This must be a multiple of 0x200.  This is added to to the base address of flash
 *               in order to compute the correct base address.
 * 
 */
static void set_vector_table_offset(uint32_t offset)
{ 
    static const uint32_t NVIC_OFFSET_FLASH = ((uint32_t)FLASH_ORIGIN);

    *SCB_VTOR = NVIC_OFFSET_FLASH | (offset & (uint32_t)0x1FFFFF80);
}

/*
 * boot_jump() - jump to application address
 *
 * INPUT - Start of application address
 * OUTPUT - none
 *
 */
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

/*
 * bootldr_init() - initialize misc initialization for bootloader
 *
 * INPUT - none
 * OUTPUT - none
 */
static void bootldr_init(void)
{
    /* Enable random */
    reset_rng();
    timer_init();
    usart_init();
    keepkey_leds_init();
    keepkey_button_init();
    display_init();
    layout_init( display_canvas() );
}

/*
 *  check_magic() - check application magic 
 *
 *  INPUT - none
 *  OUTPUT - true/false
 *
 */
static bool check_magic(void)
{
#ifndef DEBUG_ON
	bool retval = false;
    app_meta_td *app_meta = (app_meta_td *)FLASH_META_MAGIC;
    
    retval = (memcmp((void *)&app_meta->magic, META_MAGIC_STR, META_MAGIC_SIZE) == 0) ? true : false;
    return(retval);
#else
    return(true);
#endif
}

/*
 *  check_firmware_sig() - check image application partition is the 
 *                         valid keepkey firmware
 *  INPUT 
 *      - none
 *  OUTPUT
 *      - true/false
 *
 */
bool check_firmware_sig(void)
{
#ifndef DEBUG_ON
	uint32_t index;
    uint8_t (*app_meta_sig_ptr)[64] = (uint8_t (*)[])FLASH_META_SIG1;
	bool retval = false;
    app_meta_td *app_meta = (app_meta_td *)FLASH_META_START;

    for(index = 0; index < SIGNATURES; index++)
    {
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
        }
    }
	return(retval);
#else
	return(true);
#endif

}

/*
 * configure_hw() - board initialization
 *
 * INPUT - none
 * OUTPUT - none
 */
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
    rcc_periph_clock_enable(RCC_RNG);
    
}

/*
 * main - Bootloader main entry function
 *
 * INPUT - argc (not used)
 * OUTPUT - argv (not used)
 */
int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
    bool update_mode;


    configure_hw();
    bootldr_init();

#if 0 //TODO (GIT issue #49): Do not turn this on until We're ready to ship
    memory_protect();
#endif

    /* initialize stack guard with random value (-fstack_protector_all) */
    __stack_chk_guard = random32(); 

    /* button's state determines update mode. debug link will 
     * form update mode so unit tests can run */
#if DEBUG_LINK
    update_mode = true;
#else
    update_mode = keepkey_button_down();
#endif

    led_func(SET_GREEN_LED);
    led_func(SET_RED_LED);

    dbg_print("\n\rKeepKey LLC, Copyright (C) 2015\n\r");
    dbg_print("BootLoader Version %d.%d (%s)\n\r", BOOTLOADER_MAJOR_VERSION, BOOTLOADER_MINOR_VERSION, __DATE__);

    /* main loop for bootloader to transition to next step */
    if(!update_mode) {
        if(check_magic() == true) {
            if(!check_firmware_sig()) {
                /*KeepKey signature chk failed, get user acknowledgement before booting.*/
                if(!confirm_without_button_request("Unsigned Firmware Detected", 
                                                   "Do you want to continue booting?")) {
                    layout_simple_message("Boot aborted.");
                    display_refresh();
                    goto boot_exit;
                }
            }
            led_func(CLR_RED_LED);
	        cm_disable_interrupts();
            set_vector_table_offset(FLASH_APP_START - FLASH_ORIGIN);  //offset = 0x60100
            boot_jump(FLASH_APP_START);
        }
        else {
            /* Invalid magic found.  Not booting!!! */
            layout_standard_notification("INVALID FIRMWARE MAGIC",
                        "Boot aborted.",
                        NOTIFICATION_INFO);
            display_refresh();
        }
    } else {
        led_func(CLR_GREEN_LED);
        if(usb_flash_firmware()) {
                layout_standard_notification("Firmware Update Complete", 
                        "Please disconnect and reconnect.", NOTIFICATION_UNPLUG);
        } else {
                layout_standard_notification("Firmware Update Failure.", 
                        "Unable to load image.", NOTIFICATION_INFO);
        }
        display_refresh();
    }

#if DEBUG_LINK
    board_reset();
#endif

boot_exit:
    system_halt();  /* forever loop */
    return(false);  /* should never get here */
}

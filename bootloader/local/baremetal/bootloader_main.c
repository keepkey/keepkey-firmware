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
    { /* public key 1 : 0449612aa7124cb15029622b67f27e7fa7bf412fc6a74480e179209ab2fc9b6b5bd374fa2a555986145c5e8b53c32094541580ea8321521c63ae2082e89ab7ec64 */
	  0x04, 0x49, 0x61, 0x2a, 0xa7, 0x12, 0x4c, 0xb1, 0x50, 0x29, 0x62, 0x2b, 0x67, 0xf2, 0x7e, 0x7f, 0xa7, 0xbf, 0x41, 0x2f, 
      0xc6, 0xa7, 0x44, 0x80, 0xe1, 0x79, 0x20, 0x9a, 0xb2, 0xfc, 0x9b, 0x6b, 0x5b, 0xd3, 0x74, 0xfa, 0x2a, 0x55, 0x59, 0x86, 
      0x14, 0x5c, 0x5e, 0x8b, 0x53, 0xc3, 0x20, 0x94, 0x54, 0x15, 0x80, 0xea, 0x83, 0x21, 0x52, 0x1c, 0x63, 0xae, 0x20, 0x82, 
      0xe8, 0x9a, 0xb7, 0xec, 0x64
    }, 

    { /* public key 2 : 04ff887768c9565cc630c8f01396dd2b0bf520913f53f2f31e4fe92181c6ca44cad3b6e6de6912963c05631ae6cce7dc8ca72111d3c826373d104ec29185518d29*/
      0x04, 0xff, 0x88, 0x77, 0x68, 0xc9, 0x56, 0x5c, 0xc6, 0x30, 0xc8, 0xf0, 0x13, 0x96, 0xdd, 0x2b, 0x0b, 0xf5, 0x20, 0x91, 
      0x3f, 0x53, 0xf2, 0xf3, 0x1e, 0x4f, 0xe9, 0x21, 0x81, 0xc6, 0xca, 0x44, 0xca, 0xd3, 0xb6, 0xe6, 0xde, 0x69, 0x12, 0x96, 
      0x3c, 0x05, 0x63, 0x1a, 0xe6, 0xcc, 0xe7, 0xdc, 0x8c, 0xa7, 0x21, 0x11, 0xd3, 0xc8, 0x26, 0x37, 0x3d, 0x10, 0x4e, 0xc2, 
      0x91, 0x85, 0x51, 0x8d, 0x29
    },

    { /* public key 3 : 043165fc840740f8d8db33a5544f23cf63d13acbb95482cd7a7cc55f2bfa383a9d5a7ff72aadd91b981a6cc683d31a14d91f3533d3f0b2044466679072990a4424*/
	  0x04, 0x31, 0x65, 0xfc, 0x84, 0x07, 0x40, 0xf8, 0xd8, 0xdb, 0x33, 0xa5, 0x54, 0x4f, 0x23, 0xcf, 0x63, 0xd1, 0x3a, 0xcb, 
      0xb9, 0x54, 0x82, 0xcd, 0x7a, 0x7c, 0xc5, 0x5f, 0x2b, 0xfa, 0x38, 0x3a, 0x9d, 0x5a, 0x7f, 0xf7, 0x2a, 0xad, 0xd9, 0x1b, 
      0x98, 0x1a, 0x6c, 0xc6, 0x83, 0xd3, 0x1a, 0x14, 0xd9, 0x1f, 0x35, 0x33, 0xd3, 0xf0, 0xb2, 0x04, 0x44, 0x66, 0x67, 0x90, 
      0x72, 0x99, 0x0a, 0x44, 0x24
    },

    { /* public key 4 : 04723dbd8980c224073603c70e99e1b3c983a25dc039594265fd13302af9872a3acd1620c3010046b4bc806d9f9f9600899cf0d570edc2ec043471544ff67ccb6d*/
	  0x04, 0x72, 0x3d, 0xbd, 0x89, 0x80, 0xc2, 0x24, 0x07, 0x36, 0x03, 0xc7, 0x0e, 0x99, 0xe1, 0xb3, 0xc9, 0x83, 0xa2, 0x5d, 
      0xc0, 0x39, 0x59, 0x42, 0x65, 0xfd, 0x13, 0x30, 0x2a, 0xf9, 0x87, 0x2a, 0x3a, 0xcd, 0x16, 0x20, 0xc3, 0x01, 0x00, 0x46, 
      0xb4, 0xbc, 0x80, 0x6d, 0x9f, 0x9f, 0x96, 0x00, 0x89, 0x9c, 0xf0, 0xd5, 0x70, 0xed, 0xc2, 0xec, 0x04, 0x34, 0x71, 0x54, 
      0x4f, 0xf6, 0x7c, 0xcb, 0x6d
    },

    { /* public key 5 :04c5b62a94f2dbd74978d54990dac9b8f4aa4861969745f1328f196c38a2435ce595aa14c20c44889d248092935404ad84c6a4cc397d0636be0e0fd65af5cc7508*/
	  0x04, 0xc5, 0xb6, 0x2a, 0x94, 0xf2, 0xdb, 0xd7, 0x49, 0x78, 0xd5, 0x49, 0x90, 0xda, 0xc9, 0xb8, 0xf4, 0xaa, 0x48, 0x61, 
      0x96, 0x97, 0x45, 0xf1, 0x32, 0x8f, 0x19, 0x6c, 0x38, 0xa2, 0x43, 0x5c, 0xe5, 0x95, 0xaa, 0x14, 0xc2, 0x0c, 0x44, 0x88, 
      0x9d, 0x24, 0x80, 0x92, 0x93, 0x54, 0x04, 0xad, 0x84, 0xc6, 0xa4, 0xcc, 0x39, 0x7d, 0x06, 0x36, 0xbe, 0x0e, 0x0f, 0xd6, 
      0x5a, 0xf5, 0xcc, 0x75, 0x08
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
    
    retval = (memcmp((void *)&app_meta->magic, "KPKY", 4) == 0) ? true : false;

    /*
     * Make sure magic area in the flash is written.  (Magic area can be left in
     * unwritten state if usb cable was unplugged before the magic value had a chance to 
     * to update during the last flash update).  This will ensure external app can 
     * not write to the space without having to erase the sector
     */
    if((retval == false) && (app_meta->magic == 0xFFFFFFFF)){
        flash_write_n_lock(FLASH_APP, 0, META_MAGIC_SIZE, "XXXX");
    }
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
 *  check_fw_is_new - check firmware being loaded is newer than installed version
 *
 *  INPUT 
 *      - none
 *  OUTPUT
 *      - true/false
 */
bool check_fw_is_new(void)
{
    /* TODO: need to implement away to check version (stubbed for now) */
    return(true);
}

/*
 * Bootloader main entry function
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
    // update default stack guard value random value (-fstack_protector_all)
    __stack_chk_guard = random32(); 

    update_mode = keepkey_button_down();
    led_func(SET_GREEN_LED);
    led_func(SET_RED_LED);

    dbg_print("\n\rKeepKey LLC, Copyright (C) 2015\n\r");
    dbg_print("BootLoader Version %d.%d (%s)\n\r", BOOTLOADER_MAJOR_VERSION, BOOTLOADER_MINOR_VERSION, __DATE__);

    /* main loop for bootloader to transition to next step */
    while(1) {
        if(!update_mode) {
            if(check_magic() == true) {
                if(!check_firmware_sig()) {
                    /* KeepKey signature check failed.  Unknown code is sitting in Application parition */
                    layout_standard_notification("UNSIGNED FIRMWARE", "NOSIG", NOTIFICATION_INFO);
                    display_refresh();
                    delay_ms(5000);
                }
                led_func(CLR_RED_LED);
	            cm_disable_interrupts();
                set_vector_table_offset(FLASH_APP_START - FLASH_ORIGIN);  //offset = 0x60100
                boot_jump(FLASH_APP_START);
            }
            else {
                /* Invalid magic found.  Not booting!!! */
                layout_standard_notification("INVALID FIRMWARE MAGIC", 
                        "Magic value invalid in Application partition", 
                        NOTIFICATION_INFO);
                display_refresh();
                dbg_print("INVALID FIRMWARE MAGIC\n\r");
                break;
            }
        } else {
            led_func(CLR_GREEN_LED);
            if(usb_flash_firmware()) {
                layout_standard_notification("Firmware Update Complete", "Please disconnect and reconnect your KeepKey to continue.", NOTIFICATION_UNPLUG);
                display_refresh();
            } else {
                layout_standard_notification("Firmware Update Failure.", "Unable to load image", NOTIFICATION_INFO);
                display_refresh();
            }
            break;  /* break out of this loop and hang out in infinite loop */
        }
    }

    system_halt();  /* Catastrophic error, hang in forever loop */
    return(false);  /* should never get here */
}


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
 */

#include "main.h"

#include <libopencm3/stm32/desig.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/spi.h>
#include <libopencm3/stm32/f2/rng.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/cm3/cortex.h>
#include <libopencm3/cm3/scb.h>
#include <libopencm3/cm3/vector.h>

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_button.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/keepkey_leds.h"
#include "keepkey/board/keepkey_usart.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/pubkeys.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/variant.h"
#include "keepkey/board/supervise.h"
#include "keepkey/board/signatures.h"
#include "keepkey/board/u2f_hid.h"
#include "keepkey/board/util.h"
#include "keepkey/bootloader/usb_flash.h"
#include "keepkey/rand/rng.h"
#include "keepkey/variant/keepkey.h"
#include "keepkey/variant/poweredBy.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/rand.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define BUTTON_IRQN NVIC_EXTI9_5_IRQ

#define APP_VERSIONS "VERSION" \
                      VERSION_STR(BOOTLOADER_MAJOR_VERSION)  "." \
                      VERSION_STR(BOOTLOADER_MINOR_VERSION)  "." \
                      VERSION_STR(BOOTLOADER_PATCH_VERSION)

/* These variables will be used by host application to read the version info */
static const char *const application_version
__attribute__((used, section("version"))) = APP_VERSIONS;

void mmhisr(void);
void bl_board_init(void);

void memory_getDeviceSerialNo(char *str, size_t len) {
#ifdef DEBUG_ON
    desig_get_unique_id_as_string(str, len);
#else
    // Storage isn't available to be read by the bootloader, and we don't want
    // to use the Serial No. baked into the STM32 for privacy reasons.
    strlcpy(str, "000000000000000000000000", len);
#endif
}

/*
 * jump_to_firmware() - jump to firmware
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
static inline void __attribute__((noreturn)) jump_to_firmware(const vector_table_t *new_vtable, int trust)
{
    extern char _confidential_start[];
    extern char _confidential_end[];

    // Set up and turn on memory protection

    memset_reg(_confidential_start, _confidential_end, 0);

    // disable interrupts until new user vectors
    svc_disable_interrupts();    // disable interrupts until new user vectors set

#ifdef  DEBUG_ON
    // For dev devices with JTAG disabled firmware must always be trusted. Otherwise, a bootloader might be updated
    // that locks out further bootloader updates. 
    trust = SIG_OK;

#ifdef TEST_UNSIGNED
    trust = SIG_FAIL;
#endif

#endif //DEBUG_ON


    if (SIG_OK == trust) {
        if (new_vtable->irq[NVIC_ETH_IRQ] != new_vtable->irq[NVIC_ETH_WKUP_IRQ]) {
            // If these vectors are not equal, the blupdater is in the firmware space. Let it use its own vector table.
            // msp will be used in thread and handler mode. The NVIC_ETH_IRQ vector is at 0x08060234, this should
            // point to the blocking handler in the blupdater.
            // blupdater will use its own mpu
            SCB_VTOR = (uint32_t)new_vtable;                  // new vector table
            new_vtable->reset();    // jump to blupdater

        } else {
            // trusted firmware, memory protect and run unprivileged in firmware image
            SCB_VTOR = (uint32_t)new_vtable;    // use fw vector table for intermediate releases
            new_vtable->reset();    // jump to firmware
        }

    } else {
        // Untrusted firmware, run unpriv, memory protect here
        // Set the thread mode level to unprivileged for firmware without good sig, turn on mpu    
        mpu_config(trust);
        __asm__ __volatile__ ("svc %0" :: "i" (SVC_FIRMWARE_UNPRIV) : "memory"); 
    }

    // Prevent compiler from generating stack protector code (which causes CPU fault because the stack is moved)

    for (;;);
}

/*
 * bootloader_init() - Initialization for bootloader
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
static void bootloader_init(void)
{
    cm_enable_interrupts();
    reset_rng();
    timer_init();
    keepkey_button_init();
    svc_enable_interrupts();    // enable the timer and button interrupts
    usart_init();
    keepkey_leds_init();
    storage_sectorInit();
    display_hw_init();
    layout_init(display_canvas_init());
}

/*
 * clock_init() - Clock initialization
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 *
 */
static void clock_init(void)
{
    struct rcc_clock_scale clock = rcc_hse_8mhz_3v3[RCC_CLOCK_3V3_120MHZ];
    rcc_clock_setup_hse_3v3(&clock);

    rcc_periph_clock_enable(RCC_GPIOA);
    rcc_periph_clock_enable(RCC_GPIOB);
    rcc_periph_clock_enable(RCC_GPIOC);
    rcc_periph_clock_enable(RCC_OTGFS);
    rcc_periph_clock_enable(RCC_SYSCFG);
    rcc_periph_clock_enable(RCC_TIM4);
    rcc_periph_clock_enable(RCC_RNG);
    rcc_periph_clock_enable(RCC_CRC);
}

/*
 *  is_fw_update_mode() - Determines whether in firmware update mode or not
 *
 *  INPUT
 *      none
 *  OUTPUT
 *      true/false whether firmware is in update mode
 *
 */
static bool is_fw_update_mode(void)
{
#if 0 // DEBUG_LINK
    return true;
#else
    return keepkey_button_down();
#endif
}

/*
 *  magic_ok() - Check application magic
 *
 *  INPUT
 *      none
 *  OUTPUT
 *      true/false if application has correct magic
 *
 */
static bool magic_ok(void)
{
#ifndef DEBUG_ON
    bool ret_val = false;
    app_meta_td *app_meta = (app_meta_td *)FLASH_META_MAGIC;

    ret_val = (memcmp((void *)&app_meta->magic, META_MAGIC_STR,
                      META_MAGIC_SIZE) == 0) ? true : false;
    return(ret_val);
#else
    return(true);
#endif
}

const VariantInfo *variant_getInfo(void) {
    // Override the weak defintion of variant_getInfo provided by libkkboard to
    // disallow loading the VariantInfo provided by sector 4 of flash. We do
    // this so that if there's ever a case where the upload of it got
    // corrupted, then we want the bootloader to have its own fallback baked
    // in. That way, we'll be able to use normal firmware upload mechanisms to
    // fix the situation, rather than having completely bricked the device.

    const char *model = flash_getModel();
    if (!model)
        return &variant_keepkey;

#define MODEL_KK(NUMBER) \
    if (0 == strcmp(model, (NUMBER))) { \
        return &variant_keepkey; \
    }
#include "keepkey/board/models.def"

    return &variant_poweredBy;
}

/// Runs through application firmware checking, and then boots
static void boot(void)
{
    if (!magic_ok()) {
        layout_simple_message("Please visit keepkey.com/get-started");
        return;
    }

    int signed_firmware = signatures_ok();

    // Failure due to expired sig key.
    if (signed_firmware == KEY_EXPIRED) {
        layout_standard_notification("Firmware Update Required",
                                     "Please disconnect and reconnect while holding the button.",
                                     NOTIFICATION_UNPLUG);
        display_refresh();
        return;
    }

    // Signature check failed.
    if (signed_firmware != SIG_OK) {
        uint8_t flashed_firmware_hash[SHA256_DIGEST_LENGTH];
        memzero(flashed_firmware_hash, sizeof(flashed_firmware_hash));
        memory_firmware_hash(flashed_firmware_hash);
        char hash_str[2][2 * 16 + 1];
        data2hex(flashed_firmware_hash,      16, hash_str[0]);
        data2hex(flashed_firmware_hash + 16, 16, hash_str[1]);
        if (!confirm_without_button_request("Unofficial Firmware",
                                            "Do you want to continue?\n%s\n%s",
                                            hash_str[0], hash_str[1])) {
            layout_simple_message("Boot Aborted");
            return;
        }
    }

    led_func(CLR_RED_LED);
    jump_to_firmware((const vector_table_t*)(FLASH_APP_START), signed_firmware);
}

/*
 *  update_fw() - Firmware update mode
 *
 *  INPUT
 *      none
 *  OUTPUT
 *      none
 *
 */
static void update_fw(void)
{
    led_func(CLR_GREEN_LED);

    if(usb_flash_firmware())
    {
        layout_standard_notification("Firmware Update Complete",
                                     "Please disconnect and reconnect.", NOTIFICATION_UNPLUG);
        display_refresh();
    }
    else
    {
        layout_simple_message("Firmware Update Failure, Try Again");
    }
}


/*
 * main - Bootloader main entry function
 *
 * INPUT
 *     - argc: (not used)
 *     - argv: (not used)
 * OUTPUT
 *     0 when complete
 */
int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    _buttonusr_isr = (void *)&buttonisr_usr;
    _timerusr_isr = (void *)&timerisr_usr;
    _mmhusr_isr = (void *)&mmhisr;

    bl_board_init();
    clock_init();
    bootloader_init();

#if !defined(DEBUG_ON) && (MEMORY_PROTECT == 0)
#error "To compile release version, please set MEMORY_PROTECT flag"
#elif !defined(DEBUG_ON)
    /* Checks and sets memory protection */
    memory_protect();
#elif (MEMORY_PROTECT == 1)
#error "Can only compile release versions with MEMORY_PROTECT flag"
#endif

    /* Initialize stack guard with random value (-fstack_protector_all) */
    __stack_chk_guard = random32();

    led_func(SET_GREEN_LED);
    led_func(SET_RED_LED);

    dbg_print("\n\rKeepKey LLC, Copyright (C) 2018\n\r");
    dbg_print("BootLoader Version %d.%d.%d\n\r", BOOTLOADER_MAJOR_VERSION,
              BOOTLOADER_MINOR_VERSION, BOOTLOADER_PATCH_VERSION);

    if(is_fw_update_mode())
    {
        update_fw();
    }
    else
    {
        boot();
    }

#if DEBUG_LINK
    board_reset();
#else
    shutdown(); /* Loops forever */
#endif

    return(0); /* Should never get here */
}

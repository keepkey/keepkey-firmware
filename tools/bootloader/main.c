
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
#include "keepkey/board/common.h"
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

void memory_getDeviceLabel(char *str, size_t len) {
    strlcpy(str, "KeepKey", len);
}

/// Dispatch into firmware
static inline void __attribute__((noreturn)) jump_to_firmware(int trust)
{
    extern char _confidential_start[];
    extern char _confidential_end[];
    memset_reg(_confidential_start, _confidential_end, 0);

    // Disable interrupts until new user vectors are set.
    svc_disable_interrupts();

#ifdef  DEBUG_ON
    // For dev devices with JTAG disabled, firmware must always be trusted.
    // Otherwise, a bootloader might be updated that locks out further
    // bootloader updates.
    trust = SIG_OK;

#  ifdef TEST_UNSIGNED
    trust = SIG_FAIL;
#  endif

#endif

    // Set up and turn on memory protection, if needed.
    if (SIG_OK == fi_defense_delay(trust)) {

        // Trusted firmware is allowed to provide its own vtable.
        const vector_table_t *new_vtable = (const vector_table_t*)(FLASH_APP_START);

        if (new_vtable->irq[NVIC_ETH_IRQ] != new_vtable->irq[NVIC_ETH_WKUP_IRQ]) {
            // If these vectors are not equal, the blupdater is in the firmware
            // space. Let it use its own vector table. msp will be used in
            // thread and handler mode. The NVIC_ETH_IRQ vector is at
            // 0x08060234, this should point to the blocking handler in the
            // blupdater. blupdater will use its own mpu.

            // New vector table.
            SCB_VTOR = (uint32_t)new_vtable;

            // Jump to blupdater.
            new_vtable->reset();
        } else {
            // Trusted firmware, memory protect and run unprivileged in firmware image.

            // Use fw vector table for intermediate releases.
            SCB_VTOR = (uint32_t)new_vtable;

            // Jump to firmware.
            new_vtable->reset();
        }
    } else {
        // Untrusted firmware must use the bootloader's vtable, and use
        // supervisor calls to handle things like timer interrupts, and write
        // flash.

        // Configure the MPU
        mpu_config(trust);

        // Drop privileges
        __asm__ __volatile__ ("svc %0" :: "i" (SVC_FIRMWARE_UNPRIV) : "memory");
    }

    // Prevent compiler from generating stack protector code (which causes CPU
    // fault because the stack is moved)
    for (;;);
}

/// Bootloader Board Initialization
static void bootloader_init(void)
{
    cm_enable_interrupts();
    reset_rng();
    drbg_init();
    timer_init();
    keepkey_button_init();
    svc_enable_interrupts();
    usart_init();
    keepkey_leds_init();
    storage_sectorInit();
    display_hw_init();
    layout_init(display_canvas_init());
}

/// Enable the timer interrupts
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

/// \returns true iff the device should enter firmware update mode.
static bool isFirmwareUpdateMode(void)
{
    // User asked for an update.
    if (keepkey_button_down())
        return true;

    // Firmware isn't there?
    if (!magic_ok())
        return true;

    // When debugging over jtag, these are triggering, sending us into update mode.
#ifndef DEBUG_ON
    int signed_firmware = signatures_ok();

    // Check if the firmware wants us to boot into firmware update mode.
    // This is used to skip a hard reset after bootloader update, and drop the
    // user right back into the firmware update flow.
    if ((SIG_FLAG & 2) == 2)
        return true;

    // If the firmware was signed with old signing keys, we also need to update.
    if (signed_firmware == KEY_EXPIRED)
        return true;
#endif

    // Attempt to boot.
    return false;
}

bool magic_ok(void)
{
#ifndef DEBUG_ON
    app_meta_td *app_meta = (app_meta_td *)FLASH_META_MAGIC;

    return memcmp((void *)&app_meta->magic, META_MAGIC_STR,
                   META_MAGIC_SIZE) == 0;
#else
    return true;
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

/// Runs through application firmware checking, and then boots.
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
                                            "Are you willing to take the risk?\n%s\n%s",
                                            hash_str[0], hash_str[1])) {
            layout_simple_message("Boot Aborted");
            return;
        }
    }

    led_func(CLR_RED_LED);
    jump_to_firmware(signed_firmware);
}

/// Firmware update mode. Resets the device on successful firmware upload.
static void update_fw(void)
{
    led_func(CLR_GREEN_LED);

    if (usb_flash_firmware()) {
        layout_standard_notification("Firmware Update Complete",
                                     "Your device will now restart",
                                     NOTIFICATION_CONFIRMED);
        display_refresh();
        delay_ms(3000);
        board_reset();
    } else {
        layout_standard_notification("Firmware Update Failure",
                                     "There was a problem while uploading firmware. Please try again.",
                                     NOTIFICATION_UNPLUG);
        display_refresh();
    }
}

int main(void)
{
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
    __stack_chk_guard = fi_defense_delay(random32());

    led_func(SET_GREEN_LED);
    led_func(SET_RED_LED);

    dbg_print("\n\rKeepKey LLC, Copyright (C) 2018\n\r");
    dbg_print("BootLoader Version %d.%d.%d\n\r", BOOTLOADER_MAJOR_VERSION,
              BOOTLOADER_MINOR_VERSION, BOOTLOADER_PATCH_VERSION);

    storage_protect_wipe(fi_defense_delay(storage_protect_status()));

    if (isFirmwareUpdateMode()) {
        update_fw();
    } else {
        boot();
    }

    shutdown();
    return 0; // Should never get here
}


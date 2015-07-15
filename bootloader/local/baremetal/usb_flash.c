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

/* === Includes ============================================================ */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <libopencm3/stm32/flash.h>

#include <sha2.h>
#include <interface.h>
#include <keepkey_board.h>
#include <memory.h>
#include <msg_dispatch.h>
#include <keepkey_usart.h>
#include <confirm_sm.h>
#include <usb_driver.h>
#include <keepkey_flash.h>

#include "signatures.h"
#include "usb_flash.h"

/* === Variables =========================================================== */

static Allocation storage_location = FLASH_INVALID;
static FirmwareUploadState upload_state = UPLOAD_NOT_STARTED;
static ConfigFlash storage_shadow;
static uint8_t firmware_hash[SHA256_DIGEST_LENGTH];
extern bool reset_msg_stack;

static const MessagesMap_t MessagesMap[] =
{
    /* Normal Messages */
    MSG_IN(MessageType_MessageType_Initialize,              Initialize_fields,          (message_handler_t)(handler_initialize))
    MSG_IN(MessageType_MessageType_Ping,                    Ping_fields,                (message_handler_t)(handler_ping))
    MSG_IN(MessageType_MessageType_FirmwareErase,           FirmwareErase_fields,       (message_handler_t)(handler_erase))
    MSG_IN(MessageType_MessageType_ButtonAck,               ButtonAck_fields,           NO_PROCESS_FUNC)
    MSG_IN(MessageType_MessageType_Cancel,                  Cancel_fields,              NO_PROCESS_FUNC)

    /* Normal Raw Messages */
    RAW_IN(MessageType_MessageType_FirmwareUpload,          FirmwareUpload_fields,      (message_handler_t)(raw_handler_upload))

    /* Normal Out Messages */
    MSG_OUT(MessageType_MessageType_Features,               Features_fields,            NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_Success,                Success_fields,             NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_Failure,                Failure_fields,             NO_PROCESS_FUNC)
    MSG_OUT(MessageType_MessageType_ButtonRequest,          ButtonRequest_fields,       NO_PROCESS_FUNC)

#if DEBUG_LINK
    /* Debug Messages */
    DEBUG_IN(MessageType_MessageType_DebugLinkDecision,     DebugLinkDecision_fields,   NO_PROCESS_FUNC)
    DEBUG_IN(MessageType_MessageType_DebugLinkGetState,     DebugLinkGetState_fields,   (message_handler_t)(handler_debug_link_get_state))
    DEBUG_IN(MessageType_MessageType_DebugLinkStop,         DebugLinkStop_fields,       (message_handler_t)(handler_debug_link_stop))
    DEBUG_IN(MessageType_MessageType_DebugLinkFillConfig,   DebugLinkFillConfig_fields, (message_handler_t)(handler_debug_link_fill_config))

    /* Debug Out Messages */
    DEBUG_OUT(MessageType_MessageType_DebugLinkState,       DebugLinkState_fields,      NO_PROCESS_FUNC)
    DEBUG_OUT(MessageType_MessageType_DebugLinkLog,         DebugLinkLog_fields,        NO_PROCESS_FUNC)
#endif
};

/* === Private Functions =================================================== */

/*
 * check_firmware_hash - Checks flashed firmware's hash
 *
 * INPUT
 *     none
 *
 * OUTPUT
 *  status of hash check
 */
static bool check_firmware_hash(void)
{
    uint8_t flashed_firmware_hash[SHA256_DIGEST_LENGTH];

    memory_firmware_hash(flashed_firmware_hash);

    return(memcmp(firmware_hash, flashed_firmware_hash, SHA256_DIGEST_LENGTH) == 0);
}

/*
 * bootloader_fsm_init() - Initiliaze fsm for bootloader
 *
 * INPUT
 *     none
 *
 * OUTPUT
 *     update status
 */
static void bootloader_fsm_init(void)
{
    msg_map_init(MessagesMap, sizeof(MessagesMap) / sizeof(MessagesMap_t));
    set_msg_failure_handler(&send_failure);

#if DEBUG_LINK
    set_msg_debug_link_get_state_handler(&handler_debug_link_get_state);
#endif

    msg_init();
}

/*
 *  flash_locking_write - Restore storage partition in flash for firmware update
 *
 *  INPUT -
 *      - group: flash partition
 *      - offset: flash offset within partition to begin write
 *      - len: length to write
 *      - data: pointer to source data
 *
 *  OUTPUT -
 *      status of flash write
 */
static bool flash_locking_write(Allocation group, size_t offset, size_t len,
                                uint8_t *data)
{
    bool ret_val = true;

    flash_unlock();

    if(!flash_write(group, offset, len, data))
    {
        /* Flash error detectected */
        ret_val = false;
    }

    flash_lock();
    return(ret_val);
}

/*
 * storage_restore() - Restore config data
 *
 * INPUT -
 *      none
 * OUTPUT -
 *      restore status
 *
 */
static bool storage_restore(void)
{
    bool ret_val = false;

    if(storage_location >= FLASH_STORAGE1 && storage_location <= FLASH_STORAGE3)
    {
        ret_val = flash_locking_write(storage_location, 0, sizeof(ConfigFlash),
                                      (uint8_t *)&storage_shadow);
    }

    return(ret_val);
}

/*
 * storage_preserve() - Preserve storage data in ram
 *
 * INPUT -
 *      none
 * OUTPUT -
 *      preserve status
 */
static bool storage_preserve(void)
{
    bool ret_val = false;

    /* Search active storage sector and save in shadow memory  */
    if(storage_location >= FLASH_STORAGE1 && storage_location <= FLASH_STORAGE3)
    {
        memcpy(&storage_shadow, (void *)flash_write_helper(storage_location), sizeof(ConfigFlash));
        ret_val = true;
    }

    return(ret_val);
}

/* === Functions =========================================================== */

/*
 * usb_flash_firmware() - Update firmware over usb bus
 *
 * INPUT
 *     none
 *
 * OUTPUT
 *     update status
 */
bool usb_flash_firmware(void)
{
    bool ret_val = false;

    layout_simple_message("Firmware Update Mode");
#if !defined(DEBUG_ON) && defined(BUILD_ID)
    layout_version(BOOTLOADER_MAJOR_VERSION, BOOTLOADER_MINOR_VERSION,
                   BOOTLOADER_PATCH_VERSION, BUILD_ID);
#elif !defined(DEBUG_ON)
#error "Must define BUILD_ID flag when building a release version."
#else
    layout_version(BOOTLOADER_MAJOR_VERSION, BOOTLOADER_MINOR_VERSION,
                   BOOTLOADER_PATCH_VERSION, 0);
#endif

    usb_init();
    bootloader_fsm_init();

    while(1)
    {
        switch(upload_state)
        {
            case UPLOAD_COMPLETE:
            {
                /* Verify the image is from KeepKey */
                if((SIG_FLAG == 1) && (signatures_ok() == 1))
                {
                    /* The image is from KeepKey.  Restore storage data */
                    if(!storage_restore())
                    {
                        /* Bailing early */
                        goto uff_exit;
                    }
                }

                /* Check CRC of firmware that was flashed */
                if(check_firmware_hash())
                {
                    /* Fingerprint has been verified.  Install "KPKY" magic in meta header */
                    if(flash_locking_write(FLASH_APP, 0, META_MAGIC_SIZE, (uint8_t *)META_MAGIC_STR) == true)
                    {
                        send_success("Upload complete");
                        ret_val = true;
                    }
                }

                goto uff_exit;
            }

            case UPLOAD_ERROR:
            {
                dbg_print("Error: Firmware update error...\n\r");
                goto uff_exit;
            }

            case UPLOAD_NOT_STARTED:
            case UPLOAD_STARTED:
            default:
            {
                usb_poll();
                animate();
                display_refresh();
            }
        }
    }

uff_exit:
    /* Clear the shadow before exiting */
    memset(&storage_shadow, 0, sizeof(ConfigFlash));
    return(ret_val);
}

/*
 * storage_init_sect() - Find and initialize storage sector location
 *
 * INPUT
 *      none
 * OUTPUT
 *      none
 *
 */
void storage_sector_init(void)
{
    if(!find_active_storage(&storage_location))
    {
        /* Set to storage sector1 as default if no sector has been initialized */
        storage_location = STORAGE_SECT_DEFAULT;
    }
}

/* --- Message Out Writing ------------------------------------------------- */

/*
 * send_success() - Send success message to host
 *
 * INPUT
 *     - text: success message
 *
 * OUTPUT
 *     none
 *
 */

void send_success(const char *text)
{
    RESP_INIT(Success);

    if(text)
    {
        resp.has_message = true;
        strlcpy(resp.message, text, sizeof(resp.message));
    }

    msg_write(MessageType_MessageType_Success, &resp);
}

/*
 * send_falure() -  Send failure message to host
 *
 * INPUT
 *     - code: failure code
 *     - text: failure message
 *
 * OUTPUT
 *     none
 *
 */
void send_failure(FailureType code, const char *text)
{
    if(reset_msg_stack)
    {
        handler_initialize((Initialize *)0);
        reset_msg_stack = false;
        return;
    }

    RESP_INIT(Failure);

    resp.has_code = true;
    resp.code = code;

    if(text)
    {
        resp.has_message = true;
        strlcpy(resp.message, text, sizeof(resp.message));
    }

    msg_write(MessageType_MessageType_Failure, &resp);
}

/* --- Message Handlers ---------------------------------------------------- */

/*
 * handler_ping() - Handler to respond to ping message
 *
 * INPUT -
 *     - msg: ping protocol buffer message
 * OUTPUT -
 *     none
 */
void handler_ping(Ping *msg)
{
    RESP_INIT(Success);

    if(msg->has_message)
    {
        resp.has_message = true;
        memcpy(resp.message, &(msg->message), sizeof(resp.message));
    }

    msg_write(MessageType_MessageType_Success, &resp);
}

/*
 * handler_initialize() - Handler to respond to initialize message
 *
 * INPUT -
 *      - msg: initialize protocol buffer message
 * OUTPUT -
 *      none
 */
void handler_initialize(Initialize *msg)
{
    (void)msg;
    RESP_INIT(Features);

    /* Vendor */
    resp.has_vendor = true;
    strlcpy(resp.vendor, "keepkey.com", sizeof(resp.vendor));

    /* Bootloader Mode */
    resp.has_bootloader_mode = true;
    resp.bootloader_mode = true;

    /* Version */
    resp.has_major_version = true;
    resp.has_minor_version = true;
    resp.has_patch_version = true;
    resp.major_version = BOOTLOADER_MAJOR_VERSION;
    resp.minor_version = BOOTLOADER_MINOR_VERSION;
    resp.patch_version = BOOTLOADER_PATCH_VERSION;

    msg_write(MessageType_MessageType_Features, &resp);
}

/*
 * handler_erase() - Handler to wipe application firmware
 *
 * INPUT -
 *     - msg: firmware erase protocol buffer message
 * OUTPUT
 *     none
 *
 */
void handler_erase(FirmwareErase *msg)
{
    (void)msg;

    if(confirm(ButtonRequestType_ButtonRequest_FirmwareErase,
               "Verify Backup",
               "Do you have your recovery sentence in case your private keys are erased?"))
    {

        layout_simple_message("Preparing For Upgrade...");

        /* Save storage data in memory so it can be restored after firmware update */
        if(storage_preserve())
        {
            flash_unlock();

            /* Erase config data sectors  */
            for(uint32_t i = FLASH_STORAGE1; i <= FLASH_STORAGE3; i++)
            {
                flash_erase_word(i);
            }

            /* Erase application section */
            flash_erase_word(FLASH_APP);
            flash_lock();
            send_success("Firmware erased");

            layout_loading();
        }
        else
        {
            upload_state = UPLOAD_ERROR;
            send_failure(FailureType_Failure_Other, "Firmware erase error");
        }
    }
    else
    {
        upload_state = UPLOAD_ERROR;
        send_failure(FailureType_Failure_ActionCancelled, "Firmware erase cancelled");
    }
}

/* --- Raw Message Handlers ------------------------------------------------ */

/*
 * raw_handler_upload() - Main firmware upload handler that parses USB message
 * and writes image to flash
 *
 * INPUT -
 *     - msg: pointer to usb message buffer
 *     - msg_size: size of buffer
 *     - frame_length: total size that should be expected
 *
 * OUTPUT
 *     none
 *
 */
void raw_handler_upload(uint8_t *msg, uint32_t msg_size, uint32_t frame_length)
{
    static uint32_t flash_offset;

    /* Check file size is within allocated space */
    if(frame_length < (FLASH_APP_LEN + FLASH_META_DESC_LEN))
    {
        /* Start firmware load */
        if(upload_state == UPLOAD_NOT_STARTED)
        {
            upload_state = UPLOAD_STARTED;
            flash_offset = 0;

            /*
             * Parse firmware hash
             */
            memcpy(firmware_hash, msg + PROTOBUF_FIRMWARE_HASH_START, SHA256_DIGEST_LENGTH);

            /*
             * Parse application start
             */
            msg_size -= PROTOBUF_FIRMWARE_START;
            msg = (uint8_t *)(msg + PROTOBUF_FIRMWARE_START);
        }

        /* Process firmware upload */
        if(upload_state == UPLOAD_STARTED)
        {
            /* Check if the image is bigger than allocated space */
            if((flash_offset + msg_size) < (FLASH_APP_LEN + FLASH_META_DESC_LEN))
            {
                if(flash_offset == 0)
                {
                    /* Check that image is prepared with KeepKey magic */
                    if(memcmp(msg, META_MAGIC_STR, META_MAGIC_SIZE) == 0)
                    {
                        msg_size -= META_MAGIC_SIZE;
                        msg = (uint8_t *)(msg + META_MAGIC_SIZE);
                        flash_offset = META_MAGIC_SIZE;
                        /* Unlock the flash for writing */
                        flash_unlock();
                    }
                    else
                    {
                        /* Invalid KeepKey magic detected */
                        send_failure(FailureType_Failure_FirmwareError, "Not valid firmware");
                        upload_state = UPLOAD_ERROR;
                        dbg_print("Error: invalid Magic Key detected... \n\r");
                        goto rhu_exit;
                    }

                }

                /* Begin writing to flash */
                if(!flash_write(FLASH_APP, flash_offset, msg_size, msg))
                {
                    /* Error: flash write error */
                    flash_lock();
                    send_failure(FailureType_Failure_FirmwareError,
                                 "Encountered error while writing to flash");
                    upload_state = UPLOAD_ERROR;
                    dbg_print("Error: flash write error... \n\r");
                    goto rhu_exit;
                }

                flash_offset += msg_size;
            }
            else
            {
                /* Error: frame overrun detected during the image update */
                flash_lock();
                send_failure(FailureType_Failure_FirmwareError, "Firmware too large");
                upload_state = UPLOAD_ERROR;
                dbg_print("Error: frame overrun detected during the image update... \n\r");
                goto rhu_exit;
            }

            /* Finish firmware update */
            if(flash_offset >= frame_length - PROTOBUF_FIRMWARE_START)
            {
                flash_lock();
                upload_state = UPLOAD_COMPLETE;
            }
        }
    }
    else
    {
        send_failure(FailureType_Failure_FirmwareError, "Firmware too large");
        dbg_print("Error: image too large to fit in the allocated space : 0x%x ...\n\r",
                  frame_length);
        upload_state = UPLOAD_ERROR;
    }

rhu_exit:
    return;
}

/* --- Debug Message Handlers ---------------------------------------------- */

#if DEBUG_LINK
/*
 * handler_debug_link_get_state() - Handler for debug link get state
 *
 * INPUT
 *     - msg: debug link get state protocol buffer message
 *
 * OUTPUT
 *     none
 */
void handler_debug_link_get_state(DebugLinkGetState *msg)
{
    (void)msg;
    RESP_INIT(DebugLinkState);

    /* App fingerprint */
    if((resp.firmware_hash.size = memory_firmware_hash(resp.firmware_hash.bytes)) != 0)
    {
        resp.has_firmware_hash = true;
    }

    /* Storage fingerprint */
    resp.has_storage_hash = true;
    resp.storage_hash.size = memory_storage_hash(resp.storage_hash.bytes, storage_location);

    msg_debug_write(MessageType_MessageType_DebugLinkState, &resp);
}

/*
 * handler_debug_link_stop() - Handler for debug link stop
 *
 * INPUT
 *     - msg: debug link stop protocol buffer message
 *
 * OUTPUT
 *     none
 */
void handler_debug_link_stop(DebugLinkStop *msg)
{
    (void)msg;
}

/*
 * handler_debug_link_fill_config() - Fills config area with sample data (used
 * for testing firmware upload)
 *
 * INPUT
 *     - msg: debug link fill config protocol buffer message
 *
 * OUTPUT
 *     none
 */
void handler_debug_link_fill_config(DebugLinkFillConfig *msg)
{
    (void)msg;

    ConfigFlash fill_storage_shadow;

    memset((uint8_t *)&fill_storage_shadow, FILL_CONFIG_DATA, sizeof(ConfigFlash));

    /* Fill storage sector with test data */
    if(storage_location >= FLASH_STORAGE1 && storage_location <= FLASH_STORAGE3)
    {
        flash_unlock();
        flash_erase_word(storage_location);
        flash_write(storage_location, 0, sizeof(ConfigFlash),
                    (uint8_t *)&fill_storage_shadow);
        flash_lock();
    }
}
#endif

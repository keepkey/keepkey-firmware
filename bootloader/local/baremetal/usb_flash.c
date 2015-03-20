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

#include <assert.h>
#include <stdint.h>
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
#include <usb_flash.h>
#include <bootloader.h>
#include <keepkey_storage.h>
#include <keepkey_flash.h>

/*** Definition ***/
static FirmwareUploadState upload_state = UPLOAD_NOT_STARTED;
extern bool reset_msg_stack;

/*** Structure to map incoming messages to handler functions. ***/
static const MessagesMap_t MessagesMap[] = {
    // in messages
    {NORMAL_MSG, IN_MSG, MessageType_MessageType_Initialize,		Initialize_fields,      (message_handler_t)(handler_initialize)},
    {NORMAL_MSG, IN_MSG, MessageType_MessageType_Ping,				Ping_fields,            (message_handler_t)(handler_ping)},
    {NORMAL_MSG, IN_MSG, MessageType_MessageType_FirmwareErase,		FirmwareErase_fields,   (message_handler_t)(handler_erase)},
	{NORMAL_MSG, IN_MSG, MessageType_MessageType_ButtonAck,			ButtonAck_fields,		0},
	{RAW_MSG, IN_MSG, MessageType_MessageType_FirmwareUpload,		FirmwareUpload_fields,	(message_handler_t)(raw_handler_upload)},
	{NORMAL_MSG, OUT_MSG, MessageType_MessageType_Features,         Features_fields,        0},
    {NORMAL_MSG, OUT_MSG, MessageType_MessageType_Success,          Success_fields,         0},
    {NORMAL_MSG, OUT_MSG, MessageType_MessageType_Failure,          Failure_fields,         0},
	{NORMAL_MSG, OUT_MSG, MessageType_MessageType_ButtonRequest,	ButtonRequest_fields,	0},

    {END_OF_MAP, 0, 0, 0, 0}
};

static Stats stats;

/*
 * get_update_status() - get firmware update status
 *
 * INPUT - 
 *      none
 * OUTPUT - 
 *      status
 */

FirmwareUploadState get_update_status(void)
{
    return (upload_state);
}

/*
 * verify_fingerprint - verify application's finger print
 *
 * INPUT  
 *  - none
 *  
 * OUTPUT  
 *  - update status 
 */
bool verify_fingerprint(void) 
{
    char digest[SHA256_DIGEST_LENGTH];
    char str_digest[SHA256_DIGEST_STR_LEN] = "";
    uint32_t firmware_size = *(uint32_t *)FLASH_META_CODELEN ;
    bool retval = false;

    sha256_Raw((uint8_t *)FLASH_APP_START, firmware_size, digest);

    for (uint8_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        char digest_buf[BYTE_AS_HEX_STR_LEN];
        sprintf(digest_buf, "%02x", digest[i]);
        strcat(str_digest, digest_buf);
    }
	/* get user confirmation */
    if(confirm(ButtonRequestType_ButtonRequest_FirmwareCheck,
        "Compare Firmware Fingerprint", str_digest)) {
        retval = true;
    } 
    return(retval);
}

/*
 * usb_flash_firmware() - update firmware over usb bus
 *
 * INPUT  
 *  - none
 *  
 * OUTPUT  
 *  - update status 
 */
bool usb_flash_firmware(void)
{
    FirmwareUploadState upd_stat; 
    ConfigFlash storage_shadow;
    bool retval = false;

    layout_warning("Firmware Update Mode");

    /* Init message map, failure function, send init function, and usb callback */
    msg_map_init(MessagesMap);
    set_msg_failure_handler(&send_failure);
    msg_init();

    /* save storage data */
    memset(&storage_shadow, 0, sizeof(ConfigFlash));
    storage_get_end_stor(&storage_shadow);

    /* Init USB */
    if( usb_init() == false )
    {
        layout_standard_notification("USB Failure", "Unable to initialize USB", NOTIFICATION_INFO);
        display_refresh();
        delay_ms(2000);
        goto uff_exit;
    }

    /* implement timer for this loop in the future*/
    while(1)
    {
        upd_stat = get_update_status();
        switch(upd_stat)
        {
            case UPLOAD_COMPLETE:
            {
                if(check_firmware_sig())
                {
                    if(check_fw_is_new())
                    {
                        /* restore storage data to 1st block */
                        flash_write_n_lock(FLASH_STORAGE, 0, sizeof(ConfigFlash), (uint8_t *)&storage_shadow);
                    }
                }
                if(verify_fingerprint()) {
                    /* user has confirmed the finger print.  Install "KPKY" magic in flash meta header */
                    flash_write_n_lock(FLASH_APP, 0, META_MAGIC_SIZE, "KPKY");
                    send_success("Upload complete");
                    upload_state = UPLOAD_COMPLETE;
                    retval = true;
                }else {
                    send_failure(FailureType_Failure_FirmwareError, "Fingerprint is Not Confirmed");
                    upload_state = UPLOAD_ERROR;
                    retval = false;
                }
                goto uff_exit;
            }
            case UPLOAD_ERROR:
            {
                dbg_print("error: Firmware update error...\n\r");
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
    /* clear the shadow before exiting */
    memset(&storage_shadow, 0xEE, sizeof(ConfigFlash));
    return(retval);
}

/*
 * send_success() - Send success message over usb port 
 *
 * INPUT  
 *  - message string
 *  
 * OUTPUT  
 *  - none
 *
 */

void send_success(const char *text)
{
    Success s;
    memset(&s, 0, sizeof(s));

    if (text) {
        s.has_message = true;
        strlcpy(s.message, text, sizeof(s.message));
    }
    msg_write(MessageType_MessageType_Success, &s);
}

/*
 * send_falure() -  Send failure message over usb port       
 *
 * INPUT 
 *  - failure code
 *  - message string 
 *
 * OUTPUT
 *  - none
 *
 */
void send_failure(FailureType code, const char *text)
{
	if (reset_msg_stack) {
		handler_initialize((Initialize *)0);
		reset_msg_stack = false;
		return;
	}

    Failure f;
    memset(&f, 0, sizeof(f));

    f.has_code = true;
    f.code = code;
    if (text) {
        f.has_message = true;
        strlcpy(f.message, text, sizeof(f.message));
    }
    msg_write(MessageType_MessageType_Failure, &f);
}

/*
 * handler_ping() - stubbed handler
 *  
 * INPUT -
 *      none
 * OUTPUT - 
 *      none
 */
void handler_ping(Ping* msg) 
{
    (void)msg;
}

/*
 * handler_initialize() - handler to respond to usb host with bootloader 
 *      initialization values
 *
 * INPUT - 
 *      usb buffer - not used
 * OUTPUT - 
 *      none 
 */
void handler_initialize(Initialize* msg) 
{
    assert(msg != NULL);

    Features f;
    memset(&f, 0, sizeof(f));

    f.has_bootloader_mode = true;
    f.bootloader_mode = true; 
    f.has_major_version = true;
    f.major_version = BOOTLOADER_MAJOR_VERSION;
    f.minor_version= BOOTLOADER_MINOR_VERSION;
    f.patch_version = BOOTLOADER_PATCH_VERSION;

    msg_write(MessageType_MessageType_Features, &f);
}

/*
 *  flash_write_n_lock - restore storage partition in flash for firmware update
 *
 *  INPUT - 
 *      1. flash partition
 *      2. flash offset within partition to begin write
 *      3. length to write
 *      4. pointer to source data
 *
 *  OUTPUT - 
 *      none 
 */
void flash_write_n_lock(Allocation group, size_t offset, size_t len, uint8_t* dataPtr)
{
    flash_unlock();
    flash_write(group, offset, len, dataPtr);
    flash_lock();
}

/*
 *  storage_part_restore - restore storage partition in flash for firmware update
 *
 *  INPUT - 
 *      pointer to Storge partition in RAM
 *
 *  OUTPUT - 
 *      true/false 
 */
void storage_part_restore(ConfigFlash *cfg_ptr)
{
    flash_unlock();
    flash_write(FLASH_STORAGE, 0, sizeof(ConfigFlash), (uint8_t *)cfg_ptr);
    flash_lock();
}

/*
 *  storage_part_erase - restore storage partition in flash for firmware update
 *
 *  INPUT - none 
 *  OUTPUT - none 
 */
void storage_part_erase(void)
{
    flash_unlock(); 
    flash_erase(FLASH_STORAGE);  
    flash_lock();
}

/*
 * handler_erase() - The function is invoked by the host PC to erase "storage"
 *      and "application" partitions.  
 *  
 * INPUT - 
 *    *msg = unused argument
 * OUTPUT - none
 *
 */
void handler_erase(FirmwareErase* msg)
{
    if(confirm_without_button_request("Verify Backup Before Upgrade",
                "Before upgrading, confirm that you have access to the backup of your recovery sentence.")) {

        layout_simple_message("Preparing For Upgrade...");
        display_refresh();
        
        flash_unlock(); 
        flash_erase(FLASH_STORAGE);  
        flash_erase(FLASH_APP);
        flash_lock();
        send_success("Firmware Erased");

        layout_loading();
    }
}

/*
 * raw_handler_upload() - The function updates application image downloaded over the USB
 *      to application partition.  Prior to the update, it will validate image
 *      SHA256 (finger print) and install "KPKY" magic upon validation
 *
 * INPUT - 
 *     1. buffer pointer
 *     2. size of buffer
 *     3. size of file
 *
 * OUTPUT - none                 
 *
 */
void raw_handler_upload(uint8_t *msg, uint32_t msg_size, uint32_t frame_length)
{
    static uint32_t flash_offset;

    /* check file size is within allocated space */
    if( frame_length < (FLASH_APP_LEN + FLASH_META_DESC_LEN)) {
        /* Start firmware load */
        if(upload_state == UPLOAD_NOT_STARTED) {
            upload_state = UPLOAD_STARTED;
            flash_offset = 0;

            /*
            * On first USB segment of upload we have to account for added data for protocol buffers
            * which we will ignore since it is not being parsed out for us
            */
            msg_size -= PROTOBUF_FIRMWARE_PADDING;
            msg = (uint8_t*)(msg + PROTOBUF_FIRMWARE_PADDING);
        }

        /* Process firmware upload */
        if(upload_state == UPLOAD_STARTED) {
            /* check if the image is bigger than allocated space */
            if((flash_offset + msg_size) < (FLASH_APP_LEN + FLASH_META_DESC_LEN)) {
                if(flash_offset == 0) {
                    /* check image is prep'ed with KeepKey magic */
                    if(memcmp(msg, "KPKY", META_MAGIC_SIZE)) {
                        /* invalid KeepKey magic detected. Bailing!!! */
                        ++stats.invalid_msg_type_ct;
                        send_failure(FailureType_Failure_FirmwareError, "Invalid Magic Key");
                        upload_state = UPLOAD_ERROR;
                        dbg_print("error: Invalid Magic Key detected... \n\r");
                        goto rhu_exit;
                    } else {
                        msg_size -= META_MAGIC_SIZE;
                        msg = (uint8_t *)(msg + META_MAGIC_SIZE); 
                        flash_offset = META_MAGIC_SIZE; 
                        /* unlock the flash for writing */
                        flash_unlock();
                    }
                }
                /* Begin writing to flash */
                flash_write(FLASH_APP, flash_offset, msg_size, msg);
                flash_offset += msg_size;
            } else {
                /* error: frame overrun detected during the image update */
                flash_lock();
                ++stats.invalid_offset_ct;
                send_failure(FailureType_Failure_FirmwareError, "Upload overflow");
                upload_state = UPLOAD_ERROR;
                dbg_print("error: Image corruption occured during download... \n\r");
                goto rhu_exit;
            }

            /* Finish firmware update */
            if (flash_offset >= frame_length - PROTOBUF_FIRMWARE_PADDING) {
                flash_lock();
    			upload_state = UPLOAD_COMPLETE;
            }
        }
    } else {
        send_failure(FailureType_Failure_FirmwareError, "Image Too Big");
        dbg_print("error: Image too large to fit in the allocated space : 0x%x ...\n\r", frame_length);
        upload_state = UPLOAD_ERROR;
    }
rhu_exit:
    return;
}

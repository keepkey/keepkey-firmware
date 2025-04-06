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

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/keepkey_usart.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/pubkeys.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/signatures.h"
#include "keepkey/bootloader/usb_flash.h"
#include "hwcrypto/crypto/sha2.h"
#include "hwcrypto/crypto/memzero.h"
#include "keepkey/transport/interface.h"

#include "keepkey/board/supervise.h"
#include "keepkey/board/bl_mpu.h"

#include <libopencm3/stm32/flash.h>
#include <libopencm3/stm32/desig.h>

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static Allocation storage_location = FLASH_INVALID;
static RawMessageState upload_state = RAW_MESSAGE_NOT_STARTED;
static uint8_t firmware_hash[SHA256_DIGEST_LENGTH];
static bool old_firmware_was_unsigned;
extern bool reset_msg_stack;

static const MessagesMap_t MessagesMap[] = {
    /* Normal Messages */
    MSG_IN(MessageType_MessageType_Initialize, Initialize,
           handler_initialize) MSG_IN(MessageType_MessageType_GetFeatures,
                                      GetFeatures, handler_get_features)
        MSG_IN(MessageType_MessageType_Ping, Ping, handler_ping) MSG_IN(
            MessageType_MessageType_WipeDevice, WipeDevice, handler_wipe)
            MSG_IN(MessageType_MessageType_FirmwareErase, FirmwareErase,
                   handler_erase) MSG_IN(MessageType_MessageType_ButtonAck,
                                         ButtonAck, NO_PROCESS_FUNC)
                MSG_IN(MessageType_MessageType_Cancel, Cancel, NO_PROCESS_FUNC)

    /* Normal Raw Messages */
    RAW_IN(MessageType_MessageType_FirmwareUpload, FirmwareUpload,
           raw_handler_upload)

    /* Normal Out Messages */
    MSG_OUT(MessageType_MessageType_Features, Features, NO_PROCESS_FUNC)
        MSG_OUT(MessageType_MessageType_Success, Success, NO_PROCESS_FUNC)
            MSG_OUT(MessageType_MessageType_Failure, Failure, NO_PROCESS_FUNC)
                MSG_OUT(MessageType_MessageType_ButtonRequest, ButtonRequest,
                        NO_PROCESS_FUNC)

#if DEBUG_LINK
    /* Debug Messages */
    DEBUG_IN(MessageType_MessageType_DebugLinkDecision, DebugLinkDecision,
             NO_PROCESS_FUNC)
        DEBUG_IN(MessageType_MessageType_DebugLinkGetState, DebugLinkGetState,
                 handler_debug_link_get_state)
            DEBUG_IN(MessageType_MessageType_DebugLinkStop, DebugLinkStop,
                     handler_debug_link_stop)
                DEBUG_IN(MessageType_MessageType_DebugLinkFillConfig,
                         DebugLinkFillConfig, handler_debug_link_fill_config)

    /* Debug Out Messages */
    DEBUG_OUT(MessageType_MessageType_DebugLinkState, DebugLinkState,
              NO_PROCESS_FUNC) DEBUG_OUT(MessageType_MessageType_DebugLinkLog,
                                         DebugLinkLog, NO_PROCESS_FUNC)
#endif
};

/*
 * check_firmware_hash - Checks flashed firmware's hash
 *
 * INPUT
 *     none
 *
 * OUTPUT
 *  status of hash check
 */
static bool check_firmware_hash(void) {
  uint8_t flashed_firmware_hash[SHA256_DIGEST_LENGTH];

  memory_firmware_hash(flashed_firmware_hash);

  return memcmp(firmware_hash, flashed_firmware_hash, SHA256_DIGEST_LENGTH) ==
         0;
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
static void bootloader_fsm_init(void) {
  msg_map_init(MessagesMap, sizeof(MessagesMap) / sizeof(MessagesMap_t));
  set_msg_failure_handler(&send_failure);

#if DEBUG_LINK
  set_msg_debug_link_get_state_handler(&handler_debug_link_get_state);
#endif

  msg_init();
}

/// \return true iff storage should be restored after this firmware update.
static bool should_restore(void) {
  // If the firmware metadata requests a wipe, honor that.
  if (SIG_FLAG == 0) return false;

#ifdef DEBUG_ON
  return true;
#else
  // Don't restore if the old firmware was unsigned.
  //
  // This protects users of custom firmware from having their storage sectors
  // dumped, but unfortunately means they'll have to re-load keys every time
  // they update. Security >> conveniece.
  //
  // This also guarantees that when we read storage in an official firmware,
  // it must have been written by an official firmware.
  if (old_firmware_was_unsigned) return false;

  // Check the signatures of the *new* firmware.
  uint32_t sig_status = signatures_ok();

  // Otherwise both the old and new must be signed by KeepKey in order to
  // restore.
  return sig_status == SIG_OK;
#endif
}

static bool isUpdateRequired(int signed_firmware) {
  (void)signed_firmware;
  if (!magic_ok()) return true;

  if ((META_FLAGS & 1) == 1) return true;

  return false;
}

/*
 * usb_flash_firmware() - Update firmware over usb bus
 *
 * INPUT
 *     none
 *
 * OUTPUT
 *     update status
 */
bool usb_flash_firmware(void) {
  int signed_firmware = signatures_ok();
  old_firmware_was_unsigned =
      signed_firmware != SIG_OK && signed_firmware != KEY_EXPIRED;

  char serial[96 / 8 * 2 + 1];
  desig_get_unique_id_as_string(serial, sizeof(serial));

  char body[256];
  snprintf(body, sizeof(body),
             "Bootloader Version: "
             VERSION_STR(BOOTLOADER_MAJOR_VERSION) "."
             VERSION_STR(BOOTLOADER_MINOR_VERSION) "."
             VERSION_STR(BOOTLOADER_PATCH_VERSION)
             "\nSerial: %s", serial);
  layout_standard_notification(isUpdateRequired(signed_firmware)
                                   ? "FIRMWARE UPDATE REQUIRED"
                                   : "FIRMWARE UPDATE MODE",
                               body, NOTIFICATION_LOGO);
#if DEBUG_LINK
  layout_debuglink_watermark();
#endif

  usbInit("keepkey.com");
  bootloader_fsm_init();

  while (1) {
    switch (upload_state) {
      case RAW_MESSAGE_COMPLETE: {
        // Only restore the storage sector / keys if the old firmware's
        // signedness matches the new firmware's signedness.
        //
        // Also wipe if we failed to turn off storage_protect.
        if (!fi_defense_delay(should_restore()) || !storage_protect_off()) {
          flash_unlock();
          bl_flash_erase_word(FLASH_STORAGE1);
          bl_flash_erase_word(FLASH_STORAGE2);
          bl_flash_erase_word(FLASH_STORAGE3);
          flash_lock();
        }

        /* Check CRC of firmware that was flashed */
        if (check_firmware_hash()) {
          /* Fingerprint has been verified.  Install "KPKY" magic in meta header
           */
          if (flash_write(FLASH_APP, 0, META_MAGIC_SIZE,
                          (uint8_t *)META_MAGIC_STR) == true) {
            flash_lock();
            send_success("Upload complete");
            return true;
          }
        }

        flash_lock();
        return false;
      }

      case RAW_MESSAGE_ERROR: {
        flash_lock();
        dbg_print("Error: Firmware update error...\n\r");
        return false;
      }

      case RAW_MESSAGE_NOT_STARTED:
      case RAW_MESSAGE_STARTED:
      default: {
        usbPoll();
        animate();
        display_refresh();
      }
    }
  }

  /* Clear the shadow before exiting */
  flash_lock();
  return false;
}

/// Find and initialize storage sector location.
void storage_sectorInit(void) {
  if (!find_active_storage(&storage_location)) {
    /* Set to storage sector1 as default if no sector has been initialized */
    storage_location = STORAGE_SECT_DEFAULT;
  }
}

/// Send success message to host.
void send_success(const char *text) {
  RESP_INIT(Success);

  if (text) {
    resp.has_message = true;
    strlcpy(resp.message, text, sizeof(resp.message));
  }

  msg_write(MessageType_MessageType_Success, &resp);
}

/// Send failure message to host.
void send_failure(FailureType code, const char *text) {
  if (reset_msg_stack) {
    handler_initialize((Initialize *)0);
    reset_msg_stack = false;
    return;
  }

  RESP_INIT(Failure);

  resp.has_code = true;
  resp.code = code;

  if (text) {
    resp.has_message = true;
    strlcpy(resp.message, text, sizeof(resp.message));
  }

  msg_write(MessageType_MessageType_Failure, &resp);
}

/// Handler to respond to ping messages.
void handler_ping(Ping *msg) {
  RESP_INIT(Success);

  if (msg->has_message) {
    resp.has_message = true;
    memcpy(resp.message, &(msg->message), sizeof(resp.message));
  }

  msg_write(MessageType_MessageType_Success, &resp);
}

// Handler to respond to initialize message.
void handler_initialize(Initialize *msg) {
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

  /* Bootloader hash */
  resp.has_bootloader_hash = true;
  resp.bootloader_hash.size = memory_bootloader_hash(resp.bootloader_hash.bytes,
                                                     /*cached=*/false);

  /* Firmware hash */
  resp.has_firmware_hash = true;
  resp.firmware_hash.size = memory_firmware_hash(resp.firmware_hash.bytes);

  resp.policies_count = 0;

  /* Smuggle debuglink state out via policies */
  _Static_assert(1 <= sizeof(resp.policies) / sizeof(resp.policies[0]),
                 "messages.options for policies not big enough?");
  const char bl_debug_link[] = "bl_debug_link";
  _Static_assert(sizeof(bl_debug_link) <= sizeof(resp.policies[0].policy_name),
                 "Policy.policy_name not big enough");
  memcpy(resp.policies[0].policy_name, bl_debug_link, sizeof(bl_debug_link));
  resp.policies[0].has_policy_name = true;
  resp.policies[0].has_enabled = true;
#if DEBUG_LINK
  resp.policies[0].enabled = true;
#else
  resp.policies[0].enabled = false;
#endif
  resp.policies_count++;

  /* Device model */
  const char *model = flash_getModel();
  if (model) {
    resp.has_model = true;
    strlcpy(resp.model, model, sizeof(resp.model));
  }

  msg_write(MessageType_MessageType_Features, &resp);
}

/// Handler to respond to GetFeatures message.
void handler_get_features(GetFeatures *msg) {
  (void)msg;
  handler_initialize(0);
}

/// Handler to wipe all application data and secret storage.
void handler_wipe(WipeDevice *msg) {
  (void)msg;
  if (!confirm(
          ButtonRequestType_ButtonRequest_WipeDevice, "Wipe Device",
          "Do you want to erase your private keys, settings and firmware?")) {
    send_failure(FailureType_Failure_ActionCancelled, "Wipe cancelled");
    layout_home();
    return;
  }

  // Erase config data sectors.
  for (uint32_t i = FLASH_STORAGE1; i <= FLASH_STORAGE3; i++) {
    bl_flash_erase_word(i);
    layoutProgress("Erasing Secrets", (i * 1000 / 8));
  }

  // Erase application section.
  for (int i = 7; i <= 11; ++i) {
    bl_flash_erase_sector(i);
    layoutProgress("Erasing Firmware", ((i + 3 - 7 + 2) * 1000 / 8));
  }

  flash_lock();
  layoutProgress("Erasing Firmware", 1000);

  layout_home();
  send_success("Device wiped");
}

/// \returns true iff the storage has been initialized
static bool is_initialized(void) {
  Allocation storage_loc = FLASH_INVALID;
  if (find_active_storage(&storage_loc) && storage_loc != FLASH_INVALID)
    return true;
  return false;
}

/// \returns true iff the user has agreed to update their firmware
static bool should_erase(void) {
  if (is_initialized()) {
    return confirm(ButtonRequestType_ButtonRequest_FirmwareErase,
                   "Verify Backup",
                   "Do you have your recovery sentence in case your private "
                   "keys are erased?");
  } else {
    return confirm(ButtonRequestType_ButtonRequest_FirmwareErase,
                   "Firmware Update", "Do you want to update your firmware?");
  }
}

/// Handler to wipe application firmware
void handler_erase(FirmwareErase *msg) {
  (void)msg;

  if (!should_erase()) {
    upload_state = RAW_MESSAGE_ERROR;
    send_failure(FailureType_Failure_ActionCancelled,
                 "Firmware erase cancelled");
    return;
  }

  layoutProgress("Preparing for upgrade", 0);

  if (!fi_defense_delay(storage_protect_on())) {
    // Something went wrong during a prevous firmware upload, resulting in
    // the storage protection magic getting wiped. To protect the user's
    // secrets from malicious behavior, wipe them here:

    flash_unlock();

    bl_flash_erase_word(FLASH_STORAGE1);
    layoutProgress("Preparing for upgrade", 1 * 1000 / 8);

    bl_flash_erase_word(FLASH_STORAGE2);
    layoutProgress("Preparing for upgrade", 2 * 1000 / 8);

    bl_flash_erase_word(FLASH_STORAGE3);
    layoutProgress("Preparing for upgrade", 3 * 1000 / 8);

    bl_flash_erase_sector(7);
    layoutProgress("Preparing for upgrade", 4 * 1000 / 8);

    bl_flash_erase_sector(8);
    layoutProgress("Preparing for upgrade", 5 * 1000 / 8);

    bl_flash_erase_sector(9);
    layoutProgress("Preparing for upgrade", 6 * 1000 / 8);

    bl_flash_erase_sector(10);
    layoutProgress("Preparing for upgrade", 7 * 1000 / 8);

    bl_flash_erase_sector(11);
    layoutProgress("Preparing for upgrade", 8 * 1000 / 8);

    flash_lock();
  } else {
    flash_unlock();

    bl_flash_erase_sector(7);
    layoutProgress("Preparing for upgrade", 1 * 1000 / 5);

    bl_flash_erase_sector(8);
    layoutProgress("Preparing for upgrade", 2 * 1000 / 5);

    bl_flash_erase_sector(9);
    layoutProgress("Preparing for upgrade", 3 * 1000 / 5);

    bl_flash_erase_sector(10);
    layoutProgress("Preparing for upgrade", 4 * 1000 / 5);

    bl_flash_erase_sector(11);
    layoutProgress("Preparing for upgrade", 5 * 1000 / 5);

    flash_lock();
  }

  layoutProgress("Preparing for upgrade", 1000);
  send_success("Firmware erased");
}

/// Main firmware upload handler that parses USB message
void raw_handler_upload(RawMessage *msg, uint32_t frame_length) {
  static uint32_t flash_offset;

  /* Check file size is within allocated space */
  if (frame_length >= (FLASH_APP_LEN + FLASH_META_DESC_LEN)) {
    send_failure(FailureType_Failure_FirmwareError, "Firmware too large");
    dbg_print(
        "Error: image too large to fit in the allocated space : 0x%" PRIx32
        " ...\n\r",
        frame_length);
    upload_state = RAW_MESSAGE_ERROR;
    return;
  }

  /* Start firmware load */
  if (upload_state == RAW_MESSAGE_NOT_STARTED) {
    layoutProgress("Uploading Firmware", 0);

    upload_state = RAW_MESSAGE_STARTED;
    flash_offset = 0;

    /*
     * Parse firmware hash
     */
    memcpy(firmware_hash, msg->buffer + PROTOBUF_FIRMWARE_HASH_START,
           SHA256_DIGEST_LENGTH);

    /*
     * Parse application start
     */
    msg->length -= PROTOBUF_FIRMWARE_START;
    msg->buffer = (uint8_t *)(msg->buffer + PROTOBUF_FIRMWARE_START);
  }

  /* Process firmware upload */
  if (upload_state != RAW_MESSAGE_STARTED) return;

  /* Check if the image is bigger than allocated space */
  if ((flash_offset + msg->length) >= (FLASH_APP_LEN + FLASH_META_DESC_LEN)) {
    /* Error: frame overrun detected during the image update */
    flash_lock();
    send_failure(FailureType_Failure_FirmwareError, "Firmware too large");
    upload_state = RAW_MESSAGE_ERROR;
    dbg_print("Error: frame overrun detected during the image update... \n\r");
    return;
  }

  if (flash_offset == 0) {
    /* Check that image is prepared with KeepKey magic */
    if (memcmp(msg->buffer, META_MAGIC_STR, META_MAGIC_SIZE) != 0) {
      /* Invalid KeepKey magic detected */
      send_failure(FailureType_Failure_FirmwareError, "Not valid firmware");
      upload_state = RAW_MESSAGE_ERROR;
      dbg_print("Error: invalid Magic Key detected... \n\r");
      return;
    }

    msg->length -= META_MAGIC_SIZE;
    msg->buffer = (uint8_t *)(msg->buffer + META_MAGIC_SIZE);
    flash_offset = META_MAGIC_SIZE;
    /* Unlock the flash for writing */
    flash_unlock();
  }

  static int update_ctr = 60;
  if (update_ctr++ == 60) {
    layoutProgress("Uploading Firmware\n", flash_offset * 1000 / frame_length);
    update_ctr = 0;
  }

  /* Begin writing to flash */
  if (!flash_write(FLASH_APP, flash_offset, msg->length, msg->buffer)) {
    /* Error: flash write error */
    flash_lock();
    send_failure(FailureType_Failure_FirmwareError,
                 "Encountered error while writing to flash");
    upload_state = RAW_MESSAGE_ERROR;
    dbg_print("Error: flash write error... \n\r");
    return;
  }

  flash_offset += msg->length;

  /* Finish firmware update */
  if (flash_offset >= frame_length - PROTOBUF_FIRMWARE_START) {
    flash_lock();
    upload_state = RAW_MESSAGE_COMPLETE;
  }
}

#if DEBUG_LINK
void handler_debug_link_get_state(DebugLinkGetState *msg) {
  (void)msg;
  RESP_INIT(DebugLinkState);

  /* App fingerprint */
  if ((resp.firmware_hash.size =
           memory_firmware_hash(resp.firmware_hash.bytes)) != 0) {
    resp.has_firmware_hash = true;
  }

  /* Storage fingerprint */
  resp.has_storage_hash = true;
  resp.storage_hash.size =
      memory_storage_hash(resp.storage_hash.bytes, storage_location);

  msg_debug_write(MessageType_MessageType_DebugLinkState, &resp);
}

void handler_debug_link_stop(DebugLinkStop *msg) { (void)msg; }

/// Fills config area with sample data (used for testing firmware upload)
void handler_debug_link_fill_config(DebugLinkFillConfig *msg) {
  (void)msg;
  uint8_t fill_storage_shadow[STOR_FLASH_SECT_LEN];

  memset(fill_storage_shadow, FILL_CONFIG_DATA, STOR_FLASH_SECT_LEN);

  /* Fill storage sector with test data */
  if (storage_location >= FLASH_STORAGE1 &&
      storage_location <= FLASH_STORAGE3) {
    bl_flash_erase_word(storage_location);
    flash_write(storage_location, 0, STOR_FLASH_SECT_LEN, fill_storage_shadow);
  }
}
#endif

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

#ifndef EMULATOR
#include <libopencm3/stm32/flash.h>
#include <libopencm3/stm32/desig.h>
#else
#include <stdint.h>
#include <stdbool.h>
#endif

#include "keepkey/board/otp.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/supervise.h"
#include "keepkey/board/util.h"
#include "keepkey/rand/rng.h"

#include <string.h>
#include <stdint.h>

uint8_t HW_ENTROPY_DATA[HW_ENTROPY_LEN];

/*
 * flash_write_helper() - Helper function to locate starting address of
 * the functional group
 *
 * INPUT
 *     - group: functional group
 * OUTPUT
 *     starting address of functional group
 */
const uint8_t* flash_write_helper(Allocation group, size_t* pLen, size_t skip) {
  void* start = NULL;
  const FlashSector *s = flash_sector_map;

  if (pLen != NULL) *pLen = 0;
  while (s->use != FLASH_INVALID) {
    if (s->use == group && skip-- == 0) {
      start = (uint8_t*)FLASH_PTR(s->start);
      if (pLen != NULL) *pLen = s->len;
      break;
    }
    ++s;
  }

  return start;
}

/*
 * flash_chk_status() - Get flash operation status
 *
 * INPUT
 *     none
 * OUTPUT
 *     true/false flash operation status
 */
bool flash_chk_status(void) {
#ifndef EMULATOR
  if (FLASH_SR &
      (FLASH_SR_PGAERR | FLASH_SR_PGPERR | FLASH_SR_PGSERR | FLASH_SR_WRPERR)) {
    /* Flash error detected */
    return (false);
  } else {
    /* Flash operation successful */
    return (true);
  }
#else
  return true;
#endif
}

/*
 * flash_erase_word() - allows unpriv code to erase certain sectors, word size
 * at a time. DO NOT USE THIS IN PRIV MODE, WILL NOT ERASE BOOTSTRAP OR
 * BOOTLOADER SECTORS
 *
 * INPUT
 *     - group: functional group
 * OUTPUT
 *     none
 */
void flash_erase_word(Allocation group) {
#ifndef EMULATOR
  const FlashSector *s = flash_sector_map;
  while (s->use != FLASH_INVALID) {
    if (s->use == group) {
      svc_flash_erase_sector((uint32_t)s->sector);
    }
    ++s;
  }
#endif
}

/*
 * flash_write_word() - Flash write in word (32bit) size
 *
 * INPUT
 *     - group: functional group
 *     - offset: flash address offset
 *     - len: length of source data
 *     - data: pointer to source data
 * OUTPUT:
 *     true/false status of write
 */
bool flash_write_word(Allocation group, uint32_t offset, uint32_t len,
                      const uint8_t *data) {
#ifndef EMULATOR
  bool retval = true;
  intptr_t start = (intptr_t)flash_write_helper(group, NULL, 0);
  uint32_t data_word[1];
  uint32_t i, align_cnt = 0;

  start += offset;

  /* Byte writes for flash start address not long-word aligned */
  if (start % sizeof(uint32_t)) {
    align_cnt = sizeof(uint32_t) - start % sizeof(uint32_t);
    if (svc_flash_pgm_blk(start, (uint32_t)data, align_cnt) == false) {
      retval = false;
      goto fww_exit;
    }
    /* Update new start address/data & len */
    start += align_cnt;
    data += align_cnt;
    len -= align_cnt;
  }

  /* Long word writes */
  for (i = 0; i < len / sizeof(uint32_t); i++) {
    memcpy(data_word, data, sizeof(uint32_t));
    if (svc_flash_pgm_word(start, *data_word) == false) {
      retval = false;
      goto fww_exit;
    }
    start += sizeof(uint32_t);
    data += sizeof(uint32_t);
  }

  /* Byte write for last remaining bytes < longword */
  if (len % sizeof(uint32_t)) {
    if (svc_flash_pgm_blk(start, (uint32_t)data, len % sizeof(uint32_t)) ==
        false) {
      retval = false;
    }
  }
fww_exit:
  return (retval);
#else
  memcpy(flash_write_helper(group, NULL, 0) + offset, data, len);
  return true;
#endif
}

/*
 * flash_write() - Flash write in byte size
 *
 * INPUT :
 *     - group: functional group
 *     - offset: flash address offset
 *     - len: length of source data
 *     - data: source data address
 * OUTPUT:
 *     true/false status of write
 */
bool flash_write(Allocation group, uint32_t offset, uint32_t len,
                 const uint8_t *data) {
#ifndef EMULATOR
  bool retval = true;
  const uint8_t* start = flash_write_helper(group, NULL, 0);
  if (svc_flash_pgm_blk((intptr_t)(start + offset), (uint32_t)data, len) == false) {
    retval = false;
  }
  return (retval);
#else
  memcpy(flash_write_helper(group, NULL, 0) + offset, data, len);
  return true;
#endif
}

/*
 * is_mfg_mode() - Is device in manufacture mode
 *
 * INPUT -
 *      none
 * OUTPUT -
 *      none
 */
bool is_mfg_mode(void) {
#if defined(EMULATOR) || defined(DEBUG_ON)
  return false;
#else
  if (*(uint32_t *)OTP_MFG_ADDR == OTP_MFG_SIG) {
    return false;
  }

  return true;
#endif
}

/*
 * set_mfg_mode_off() - Set manufacture mode off and lock the block
 *
 * INPUT -
 *      none
 * OUTPUT -
 *      none
 */
bool set_mfg_mode_off(void) {
  bool ret_val = false;
  uint32_t tvar;

#ifndef EMULATOR
  /* check OTP lock state before updating */
  if (*(uint8_t *)OTP_BLK_LOCK(OTP_MFG_ADDR) == 0xFF) {
    tvar = OTP_MFG_SIG; /* set manufactur'ed signature */
    svc_flash_pgm_blk(OTP_MFG_ADDR, (uint32_t)((uint8_t *)&tvar),
                      OTP_MFG_SIG_LEN);
    tvar = 0x00; /* set OTP lock */
    if (svc_flash_pgm_blk(OTP_BLK_LOCK(OTP_MFG_ADDR),
                          (uint32_t)((uint8_t *)&tvar), 1)) {
      ret_val = true;
    }
  }
#endif

  return (ret_val);
}

const char *flash_getModel(void) {
#ifndef EMULATOR

#ifdef DEBUG_ON
  return "K1-14AM";  // return a model number for debugger builds
#endif

  if (*((uint8_t *)OTP_MODEL_ADDR) == 0xFF) return NULL;

  return (char *)OTP_MODEL_ADDR;
#else
  // TODO: actually make this settable in the emulator
  return "K1-14AM";
#endif
}

bool flash_setModel(const char* buf, size_t len) {
  if (len > MODEL_STR_SIZE - 1) return false;
#ifdef EMULATOR
  return true;
#else
  char model[MODEL_STR_SIZE] = { 0 };
  memcpy(model, buf, len);

  // Check OTP lock state before updating
  if (*(uint8_t *)OTP_BLK_LOCK(OTP_MODEL_ADDR) != 0xFF) return false;

  svc_flash_pgm_blk(OTP_MODEL_ADDR, (uint32_t)((uint8_t *)model),
                    sizeof(*model));
  uint8_t lock = 0x00;
  return svc_flash_pgm_blk(OTP_BLK_LOCK(OTP_MODEL_ADDR), (uint32_t)&lock, sizeof(lock));
#endif
}

void flash_collectHWEntropy(bool privileged) {
#ifdef EMULATOR
  (void)privileged;
  memset(HW_ENTROPY_DATA, 0, HW_ENTROPY_LEN);
#else
  if (privileged) {
    desig_get_unique_id((uint32_t *)HW_ENTROPY_DATA);
    // set entropy in the OTP randomness block
    if (!flash_otp_is_locked(FLASH_OTP_BLOCK_RANDOMNESS)) {
      uint8_t entropy[FLASH_OTP_BLOCK_SIZE] = {0};
      random_buffer(entropy, FLASH_OTP_BLOCK_SIZE);
      flash_otp_write(FLASH_OTP_BLOCK_RANDOMNESS, 0, entropy,
                      FLASH_OTP_BLOCK_SIZE);
      flash_otp_lock(FLASH_OTP_BLOCK_RANDOMNESS);
    }
    // collect entropy from OTP randomness block
    flash_otp_read(FLASH_OTP_BLOCK_RANDOMNESS, 0, HW_ENTROPY_DATA + 12,
                   FLASH_OTP_BLOCK_SIZE);
  } else {
    // unprivileged mode => use fixed HW_ENTROPY
    memset(HW_ENTROPY_DATA, 0x3C, HW_ENTROPY_LEN);
  }
#endif
}

size_t flash_readHWEntropy(uint8_t *buf, size_t len) {
  size_t actualSize = MIN(sizeof(HW_ENTROPY_DATA), len);
  memcpy(buf, HW_ENTROPY_DATA, actualSize);
  return actualSize;
}

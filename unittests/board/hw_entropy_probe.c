/* Compile the actual boot entry point's hardware branch. Only the register,
 * OTP, RNG and halt dependencies are substituted; the emulator branch would
 * otherwise zero the entropy without ever exercising first-boot failure. */
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>

#include "hw_entropy_probe.h"

#define HW_ENTROPY_DATA probe_hw_entropy
#define flash_collectHWEntropy probe_collect_hw_entropy
#define flash_readHWEntropy probe_read_hw_entropy
#define flash_write_helper probe_flash_write_helper
#define flash_chk_status probe_flash_chk_status
#define flash_erase_word probe_flash_erase_word
#define flash_write_word probe_flash_write_word
#define flash_write probe_flash_write
#define is_mfg_mode probe_is_mfg_mode
#define set_mfg_mode_off probe_set_mfg_mode_off
#define flash_getModel probe_flash_getModel
#define flash_setModel probe_flash_setModel
#define flash_programModel probe_flash_programModel
#define flash_otp_is_locked probe_otp_is_locked
#define flash_otp_write probe_otp_write
#define flash_otp_lock probe_otp_lock
#define flash_otp_read probe_otp_read
#define random_buffer_checked probe_random_buffer_checked
#define shutdown probe_shutdown
#define svc_flash_erase_sector probe_svc_flash_erase_sector
#define svc_flash_pgm_blk probe_svc_flash_pgm_blk
#define svc_flash_pgm_word probe_svc_flash_pgm_word

// Board declarations retain their native USB types; the implementation below
// alone selects the device branch. No board initialization is performed.
#include "keepkey/board/keepkey_board.h"
#undef EMULATOR

/* Uncalled flash-programming paths contain 32-bit hardware addresses. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
#include "../../lib/board/keepkey_flash.c"
#pragma GCC diagnostic pop

static HwEntropyProbe observed;
static jmp_buf halt_target;
static bool healthy_draw;
static HwEntropyFault fault;
static uint8_t* live_draw;
/* Each boot draws different bytes, so rewriting a programmed block with a
 * fresh draw cannot verify by coincidence. First boots use salt 0. */
static uint8_t draw_salt;

static bool all_zero(const uint8_t* bytes, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    if (bytes[i]) return false;
  }
  return true;
}

void desig_get_unique_id(uint32_t* result) {
  const uint32_t id[3] = {0x03020100, 0x07060504, 0x0b0a0908};
  memcpy(result, id, sizeof(id));
}

bool probe_otp_is_locked(uint8_t block) {
  if (block != FLASH_OTP_BLOCK_RANDOMNESS) abort();
  return observed.locked;
}

bool probe_random_buffer_checked(uint8_t* bytes, size_t size) {
  if (size != FLASH_OTP_BLOCK_SIZE) abort();
  ++observed.draws;
  live_draw = bytes;
  // Deliberately leave nonzero rejected bytes so the caller's own cleanup is
  // checked independently of random_buffer_checked()'s existing zeroing.
  for (size_t i = 0; i < size; ++i)
    bytes[i] = (uint8_t)((0x40 + i) ^ draw_salt);
  return healthy_draw;
}

/* Programming OTP can only clear bits, as on the device. The partial fault
 * loses power after half the block, so later pulses have no effect. */
bool probe_otp_write(uint8_t block, uint8_t offset, const uint8_t* bytes,
                     uint8_t size) {
  if (block != FLASH_OTP_BLOCK_RANDOMNESS ||
      offset + size > FLASH_OTP_BLOCK_SIZE || observed.locked)
    abort();
  ++observed.writes;
  if (fault == OTP_WRITE_REJECTED) return false;
  if (fault == OTP_WRITE_DROPPED) return true;
  for (uint8_t i = 0; i < size; ++i) {
    if (fault == OTP_WRITE_PARTIAL && offset + i >= FLASH_OTP_BLOCK_SIZE / 2)
      break;
    observed.otp[offset + i] &= bytes[i];
  }
  return true;
}

bool probe_otp_lock(uint8_t block) {
  if (block != FLASH_OTP_BLOCK_RANDOMNESS) abort();
  ++observed.locks;
  observed.reads_before_lock = observed.reads;
  if (fault == OTP_LOCK_REJECTED) return false;
  if (fault == OTP_LOCK_DROPPED) return true;
  observed.locked = true;
  return true;
}

bool probe_otp_read(uint8_t block, uint8_t offset, uint8_t* bytes,
                    uint8_t size) {
  if (block != FLASH_OTP_BLOCK_RANDOMNESS || offset ||
      size != FLASH_OTP_BLOCK_SIZE)
    abort();
  ++observed.reads;
  if (fault == OTP_READ_REJECTED) {
    memset(bytes, 0x27, size);
    return false;
  }
  memcpy(bytes, observed.otp, size);
  return true;
}

void __attribute__((noreturn)) probe_shutdown(void) {
  observed.halted = true;
  observed.local_cleared = live_draw && all_zero(live_draw, 32);
  observed.global_cleared = all_zero(probe_hw_entropy, 44);
  longjmp(halt_target, 1);
}

// These are outside the entropy entry point; invoking one invalidates a test.
void probe_svc_flash_erase_sector(uint32_t sector) {
  (void)sector;
  abort();
}
bool probe_svc_flash_pgm_blk(uint32_t start, uint32_t data, uint32_t size) {
  (void)start;
  (void)data;
  (void)size;
  abort();
}
bool probe_svc_flash_pgm_word(uint32_t start, uint32_t data) {
  (void)start;
  (void)data;
  abort();
}

static HwEntropyProbe boot(bool privileged, bool locked, bool healthy,
                           const uint8_t* otp, HwEntropyFault injected_fault) {
  memset(&observed, 0, sizeof(observed));
  memcpy(observed.otp, otp, sizeof(observed.otp));
  memset(probe_hw_entropy, 0xa5, sizeof(probe_hw_entropy));
  observed.locked = locked;
  healthy_draw = healthy;
  fault = injected_fault;
  live_draw = NULL;
  if (!setjmp(halt_target)) {
    probe_collect_hw_entropy(privileged);
    observed.returned = true;
  }
  probe_read_hw_entropy(observed.collected, sizeof(observed.collected));
  return observed;
}

HwEntropyProbe test_collect_hw_entropy(bool privileged, bool locked,
                                       bool healthy, uint8_t stored_byte,
                                       HwEntropyFault injected_fault) {
  uint8_t otp[sizeof(observed.otp)];
  memset(otp, stored_byte, sizeof(otp));
  draw_salt = 0;
  return boot(privileged, locked, healthy, otp, injected_fault);
}

HwEntropyProbe test_reboot_hw_entropy(const HwEntropyProbe* previous,
                                      bool healthy,
                                      HwEntropyFault injected_fault) {
  draw_salt = TEST_REBOOT_DRAW_SALT;
  return boot(true, previous->locked, healthy, previous->otp, injected_fault);
}

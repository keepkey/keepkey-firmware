#ifndef HW_ENTROPY_PROBE_H
#define HW_ENTROPY_PROBE_H
#include <stdbool.h>
#include <stdint.h>

typedef struct {
  unsigned draws, writes, locks, reads, reads_before_lock;
  bool locked, halted, returned, local_cleared, global_cleared;
  uint8_t otp[32], collected[44];
} HwEntropyProbe;

typedef enum {
  OTP_HEALTHY,
  OTP_WRITE_REJECTED,
  OTP_WRITE_DROPPED,
  OTP_WRITE_PARTIAL,
  OTP_READ_REJECTED,
  OTP_LOCK_REJECTED,
  OTP_LOCK_DROPPED,
} HwEntropyFault;

HwEntropyProbe test_collect_hw_entropy(bool privileged, bool locked,
                                       bool healthy, uint8_t stored_byte,
                                       HwEntropyFault fault);
/* Boot again on the OTP contents and lock state a previous boot left. That
 * boot draws byte i as (0x40 + i) ^ TEST_REBOOT_DRAW_SALT; first boots draw
 * 0x40 + i. */
#define TEST_REBOOT_DRAW_SALT 0x21
HwEntropyProbe test_reboot_hw_entropy(const HwEntropyProbe* previous,
                                      bool healthy, HwEntropyFault fault);
#endif

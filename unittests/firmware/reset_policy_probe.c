/* Native-only fixture: compile the production reset implementation with known
 * entropy and local approval/input substitutes. No fixture is linked into kkemu
 * or ARM firmware and no secret-reading transport is used as an oracle. */
#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/dice_input.h"
#include "keepkey/rand/rng.h"
#include "keepkey/rand/rng_health.h"
#include "trezor/crypto/rand.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static bool probe_enabled;
static int fail_phase;
static unsigned seen_phases;
static unsigned disclosure_errors;
static char observed_entropy_words[512];
static char observed_backup_words[512];
static bool probe_random(uint8_t*, size_t);
static bool probe_collect(char*, uint32_t);
static bool probe_confirm(ButtonRequestType, const char*, const char*, ...);
static bool probe_paged(ButtonRequestType, const char*, const char*);
#define random_buffer_checked probe_random
#define dice_input_collect probe_collect
#define confirm probe_confirm
#define confirm_constant_power_paged probe_paged
#include "../../lib/firmware/reset.c"
#undef random_buffer_checked
#undef dice_input_collect
#undef confirm
#undef confirm_constant_power_paged

static bool observe(int phase) {
  seen_phases |= 1u << phase;
  uint8_t bytes[32];
  memset(bytes, 0xa5, sizeof(bytes));
  if (!reset_debug_is_private() || reset_get_int_entropy(bytes) != 0 ||
      reset_get_word()[0] != '\0' || reset_get_dice_digest(bytes) != 0)
    disclosure_errors++;
  for (size_t i = 0; i < sizeof(bytes); ++i)
    if (bytes[i] != 0xa5) disclosure_errors++;
  return fail_phase != phase;
}

static bool probe_random(uint8_t* out, size_t count) {
  if (!probe_enabled) return random_buffer_checked(out, count);
  for (size_t i = 0; i < count; ++i) out[i] = (uint8_t)i;
  return true;
}
static bool probe_collect(char* rolls, uint32_t count) {
  if (!probe_enabled) return dice_input_collect(rolls, count);
  if (!observe(3)) return false;
  for (uint32_t i = 0; i < count; ++i) rolls[i] = '1' + i % 6;
  return true;
}
static bool probe_confirm(ButtonRequestType type, const char* title,
                          const char* format, ...) {
  if (probe_enabled)
    return observe(type == ButtonRequestType_ButtonRequest_DiceRoll ? 1 : 5);
  char body[1024];
  va_list args;
  va_start(args, format);
  vsnprintf(body, sizeof(body), format, args);
  va_end(args);
  return confirm(type, title, "%s", body);
}
static bool probe_paged(ButtonRequestType type, const char* title,
                        const char* body) {
  if (!probe_enabled) return confirm_constant_power_paged(type, title, body);
  int phase = strncmp(title, "Entropy", 7) == 0  ? 2
              : strncmp(title, "Backup", 6) == 0 ? 6
                                                 : 4;
  // Inspect device-side logical pages directly in this native fixture.
  // The wire test independently asserts the complete DebugLinkState is empty.
  char* words = phase == 2 ? observed_entropy_words : observed_backup_words;
  if (phase == 2 || phase == 6) {
    if (words[0]) strlcat(words, " ", 512);
    strlcat(words, current_words, 512);
  }
  return observe(phase);
}
void reset_probe_begin(int abort_phase) {
  setup_abort();
  probe_enabled = true;
  fail_phase = abort_phase;
  seen_phases = disclosure_errors = 0;
  memset(observed_entropy_words, 0, sizeof(observed_entropy_words));
  memset(observed_backup_words, 0, sizeof(observed_backup_words));
}
void reset_probe_end(void) {
  setup_abort();
  probe_enabled = false;
}
unsigned reset_probe_seen(void) { return seen_phases; }
unsigned reset_probe_errors(void) { return disclosure_errors; }
const char* reset_probe_entropy_words(void) { return observed_entropy_words; }
const char* reset_probe_backup_words(void) { return observed_backup_words; }

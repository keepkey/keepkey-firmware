#ifndef KEEPKEY_FIRMWARE_ERC7730_CAPABILITIES_H
#define KEEPKEY_FIRMWARE_ERC7730_CAPABILITIES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "keepkey/firmware/erc7730_program.h"

/* The preload verifier and the runtime check these same predicates, so a
 * preloaded definition cannot fail mid-review. Widen only with the runtime,
 * and keep python-keepkey's DEVICE_CAPABILITIES in step. */

#define ERC7730_CAP_BIT(n) (UINT32_C(1) << (n))

/* 1 intent, 2/3 intent text/value (numbered parts right after the intent),
 * 4 field, 5/6 group, 7/8 iteration over one array, 10 end. */
#define ERC7730_CAP_DISPLAY_OPCODES                               \
  (ERC7730_CAP_BIT(1) | ERC7730_CAP_BIT(2) | ERC7730_CAP_BIT(3) | \
   ERC7730_CAP_BIT(4) | ERC7730_CAP_BIT(5) | ERC7730_CAP_BIT(6) | \
   ERC7730_CAP_BIT(7) | ERC7730_CAP_BIT(8) | ERC7730_CAP_BIT(10))
/* 1 raw, 2 amount, 3 tokenAmount, 4 nftName, 5 date, 6 duration, 7 unit,
 * 8 enum, 10 addressName, 13 embedded calldata (calldata definitions only;
 * selector role 16 unused, the device reads it from the inner bytes). */
#define ERC7730_CAP_FORMATTER_KINDS                                \
  (ERC7730_CAP_BIT(1) | ERC7730_CAP_BIT(2) | ERC7730_CAP_BIT(3) |  \
   ERC7730_CAP_BIT(4) | ERC7730_CAP_BIT(5) | ERC7730_CAP_BIT(6) |  \
   ERC7730_CAP_BIT(7) | ERC7730_CAP_BIT(8) | ERC7730_CAP_BIT(10) | \
   ERC7730_CAP_BIT(13))
/* Path sources: 1 value, 2 container, 3 literal. */
#define ERC7730_CAP_PATH_SOURCES \
  (ERC7730_CAP_BIT(1) | ERC7730_CAP_BIT(2) | ERC7730_CAP_BIT(3))
/* Step opcodes: 1 index, 2 every element. Slices (3) are not executed. */
#define ERC7730_CAP_PATH_STEP_OPCODES (ERC7730_CAP_BIT(1) | ERC7730_CAP_BIT(2))
/* Calldata only: 1 @.from (derived on device), 2 @.to, 3 @.value. */
#define ERC7730_CAP_CONTAINERS \
  (ERC7730_CAP_BIT(1) | ERC7730_CAP_BIT(2) | ERC7730_CAP_BIT(3))
/* Only "optional" (3), which is always shown: conditions hide nothing. */
#define ERC7730_CAP_CONDITION_OPCODES ERC7730_CAP_BIT(3)
/* A tokenAmount native-currency alias set may name at most this many
 * addresses, so the runtime can hold their literal indices. */
#define ERC7730_CAP_ALIAS_SET_MAX 4u
/* Escaped (<=4 chars a byte) signer text must fit the screen and buffers. */
#define ERC7730_CAP_SIGNER_TEXT_MAX 64u
/* unit decimals at most this: a uint256 has at most 78 digits, so larger
 * scalings only prepend zeros. */
#define ERC7730_CAP_UNIT_DECIMALS_MAX 77u
/* An enum map may hold at most this many entries (the registry's largest has
 * ten), so the runtime can hold their key and label indices. */
#define ERC7730_CAP_ENUM_MAX 16u

/* Value class: 1-7 are ABI leaf kinds; literals map to what they hold. */
enum {
  ERC7730_CLASS_NONE = 0,
  ERC7730_CLASS_UINT = 1,
  ERC7730_CLASS_INT = 2,
  ERC7730_CLASS_ADDRESS = 3,
  ERC7730_CLASS_BOOL = 4,
  ERC7730_CLASS_BYTES = 6,
  ERC7730_CLASS_STRING = 7,      /* also any program string (source 3) */
  ERC7730_CLASS_STRING_REF = 8,  /* literal kind 4: an index into strings */
  ERC7730_CLASS_ALIAS_SET = 9,   /* literal kind 9 of at most ALIAS_SET_MAX */
  ERC7730_CLASS_UINT_SMALL = 10, /* literal kind 1 of one byte: 0-255 */
  ERC7730_CLASS_DATE_ENCODING = 11, /* the string "timestamp" or "blockheight"
                                     */
  ERC7730_CLASS_ENUM_MAP = 12,      /* literal kind 8 of at most ENUM_MAX */
  ERC7730_CLASS_FLAG = 13,          /* literal kind 6: a boolean */
};

/* The class of a literal of kind `kind`. `extent` is its length for kind 1
 * and its member count for kinds 8 and 9. */
uint8_t erc7730_cap_literal_class(uint8_t kind, uint16_t extent);
/* The class of program string `text`: a date encoding, or any string. */
uint8_t erc7730_cap_string_class(const char* text, size_t length);
/* Whether argument `role` of formatter `kind` may carry a value of `cls`. */
bool erc7730_cap_value(uint8_t kind, uint8_t role, uint8_t cls);

uint32_t erc7730_cap_formatter_required_roles(uint8_t kind);
uint8_t erc7730_cap_argument_sources(uint8_t kind, uint8_t role);

bool erc7730_cap_display(const Erc7730DisplayInstruction* instruction,
                         uint16_t pc);
bool erc7730_cap_formatter(const Erc7730Formatter* formatter);
bool erc7730_cap_path(const Erc7730Path* path);

#endif

#include "keepkey/firmware/erc7730_capabilities.h"

#include <string.h>

/* Per formatter kind: the roles it may carry, those it requires, and for each
 * role the permitted sources (a bitmask of ERC7730_CAP_BIT(source)). */
typedef struct {
  uint8_t role;
  uint8_t sources;
} Erc7730RoleSources;

#define PATH ((uint8_t)ERC7730_CAP_BIT(1))
#define LITERAL ((uint8_t)ERC7730_CAP_BIT(2))
#define STRING ((uint8_t)ERC7730_CAP_BIT(3))

static const Erc7730RoleSources* formatter_roles(uint8_t kind, size_t* count,
                                                 uint32_t* required) {
  static const Erc7730RoleSources value_only[] = {{1, PATH}};
  static const Erc7730RoleSources token_amount[] = {
      {1, PATH}, {2, PATH}, {7, LITERAL}, {8, STRING}, {22, LITERAL}};
  static const Erc7730RoleSources nft[] = {{1, PATH}, {3, PATH}};
  static const Erc7730RoleSources date[] = {{1, PATH}, {9, STRING}};
  static const Erc7730RoleSources unit[] = {
      {1, PATH}, {4, LITERAL}, {5, STRING}, {6, LITERAL}};
  static const Erc7730RoleSources enumeration[] = {{1, PATH}, {10, LITERAL}};
  static const Erc7730RoleSources embedded[] = {
      {1, PATH}, {15, PATH}, {17, PATH}, {18, PATH}};
  *required = ERC7730_CAP_BIT(1);
  if (kind > 31 || (ERC7730_CAP_FORMATTER_KINDS & ERC7730_CAP_BIT(kind)) == 0) {
    *count = 0;
    *required = 0;
    return NULL;
  }
  switch (kind) {
    case 3:
      *required |= ERC7730_CAP_BIT(2);
      *count = sizeof(token_amount) / sizeof(token_amount[0]);
      return token_amount;
    case 4:
      *required |= ERC7730_CAP_BIT(3);
      *count = sizeof(nft) / sizeof(nft[0]);
      return nft;
    case 5:
      *count = sizeof(date) / sizeof(date[0]);
      return date;
    case 7:
      *required |= ERC7730_CAP_BIT(5);
      *count = sizeof(unit) / sizeof(unit[0]);
      return unit;
    case 8:
      *required |= ERC7730_CAP_BIT(10);
      *count = sizeof(enumeration) / sizeof(enumeration[0]);
      return enumeration;
    case 13:
      *required |= ERC7730_CAP_BIT(15);
      *count = sizeof(embedded) / sizeof(embedded[0]);
      return embedded;
    default: /* 1 raw, 2 amount, 6 duration, 10 addressName */
      *count = 1;
      return value_only;
  }
}

uint32_t erc7730_cap_formatter_required_roles(uint8_t kind) {
  size_t count;
  uint32_t required;
  formatter_roles(kind, &count, &required);
  return required;
}

uint8_t erc7730_cap_argument_sources(uint8_t kind, uint8_t role) {
  size_t count;
  uint32_t required;
  const Erc7730RoleSources* table = formatter_roles(kind, &count, &required);
  for (size_t i = 0; i < count; i++)
    if (table[i].role == role) return table[i].sources;
  return 0;
}

uint8_t erc7730_cap_literal_class(uint8_t kind, uint16_t extent) {
  switch (kind) {
    case 1:
      return extent == 1 ? ERC7730_CLASS_UINT_SMALL : ERC7730_CLASS_UINT;
    case 4:
      return ERC7730_CLASS_STRING_REF;
    case 5:
      return ERC7730_CLASS_ADDRESS;
    case 6:
      return ERC7730_CLASS_FLAG;
    case 8:
      return extent != 0 && extent <= ERC7730_CAP_ENUM_MAX
                 ? ERC7730_CLASS_ENUM_MAP
                 : ERC7730_CLASS_NONE;
    case 9:
      return extent != 0 && extent <= ERC7730_CAP_ALIAS_SET_MAX
                 ? ERC7730_CLASS_ALIAS_SET
                 : ERC7730_CLASS_NONE;
    default:
      return ERC7730_CLASS_NONE;
  }
}

uint8_t erc7730_cap_string_class(const char* text, size_t length) {
  if (text && ((length == 9 && memcmp(text, "timestamp", 9) == 0) ||
               (length == 11 && memcmp(text, "blockheight", 11) == 0)))
    return ERC7730_CLASS_DATE_ENCODING;
  return ERC7730_CLASS_STRING;
}

static bool unsigned_class(uint8_t cls) {
  return cls == ERC7730_CLASS_UINT || cls == ERC7730_CLASS_UINT_SMALL;
}

bool erc7730_cap_value(uint8_t kind, uint8_t role, uint8_t cls) {
  if (cls == ERC7730_CLASS_NONE) return false;
  switch (kind) {
    case 1: /* raw: an ABI leaf, an integer, an address or a string */
      return role == 1 && (cls <= ERC7730_CLASS_STRING_REF ||
                           cls == ERC7730_CLASS_UINT_SMALL);
    case 10: /* addressName */
      return role == 1 && cls == ERC7730_CLASS_ADDRESS;
    case 2: /* amount */
    case 6: /* duration */
      return role == 1 && cls == ERC7730_CLASS_UINT;
    case 3: /* tokenAmount */
      switch (role) {
        case 1:
          return cls == ERC7730_CLASS_UINT;
        case 7:
          return unsigned_class(cls);
        case 2:
          return cls == ERC7730_CLASS_ADDRESS;
        case 8:
          return cls == ERC7730_CLASS_STRING ||
                 cls == ERC7730_CLASS_DATE_ENCODING;
        case 22:
          return cls == ERC7730_CLASS_ALIAS_SET;
        default:
          return false;
      }
    case 4: /* nftName: token id, collection */
      return (role == 1 && cls == ERC7730_CLASS_UINT) ||
             (role == 3 && cls == ERC7730_CLASS_ADDRESS);
    case 5: /* date: value, encoding */
      return (role == 1 && cls == ERC7730_CLASS_UINT) ||
             (role == 9 && cls == ERC7730_CLASS_DATE_ENCODING);
    case 7: /* unit: value, decimals, base, prefix */
      return (role == 1 && cls == ERC7730_CLASS_UINT) ||
             (role == 4 && cls == ERC7730_CLASS_UINT_SMALL) ||
             (role == 5 && (cls == ERC7730_CLASS_STRING ||
                            cls == ERC7730_CLASS_DATE_ENCODING)) ||
             (role == 6 && cls == ERC7730_CLASS_FLAG);
    case 13: /* embedded calldata: inner bytes, callee, value, authority */
      return (role == 1 && cls == ERC7730_CLASS_BYTES) ||
             (role == 15 && cls == ERC7730_CLASS_ADDRESS) ||
             (role == 17 && cls == ERC7730_CLASS_UINT) ||
             (role == 18 && cls == ERC7730_CLASS_ADDRESS);
    case 8: /* enum: value, map */
      return (role == 1 &&
              (cls == ERC7730_CLASS_UINT || cls == ERC7730_CLASS_INT ||
               cls == ERC7730_CLASS_BOOL)) ||
             (role == 10 && cls == ERC7730_CLASS_ENUM_MAP);
    default:
      return false;
  }
}

bool erc7730_cap_display(const Erc7730DisplayInstruction* instruction,
                         uint16_t pc) {
  if (!instruction || instruction->flags != 0 || instruction->opcode > 31 ||
      (ERC7730_CAP_DISPLAY_OPCODES & ERC7730_CAP_BIT(instruction->opcode)) == 0)
    return false;
  const uint16_t a = instruction->a, b = instruction->b, c = instruction->c;
  switch (instruction->opcode) {
    case 1: /* intent: string a, and only as the first instruction */
      return pc == 0 && a != UINT16_MAX && b == UINT16_MAX && c == UINT16_MAX;
    case 2: /* intent text: string a */
    case 3: /* intent value: formatter a */
      return pc != 0 && a != UINT16_MAX && b == UINT16_MAX && c == UINT16_MAX;
    case 4: /* field: label string a, formatter b, optional condition c */
      return pc != 0 && a != UINT16_MAX && b != UINT16_MAX;
    case 5: /* group begin: optional label a, optional condition b, end c */
      return pc != 0 && c != UINT16_MAX;
    case 6: /* group end: begin a */
      return pc != 0 && a != UINT16_MAX && b == UINT16_MAX && c == UINT16_MAX;
    case 7: /* iteration begin: array path a, optional condition b, end c */
      return pc != 0 && a != UINT16_MAX && c != UINT16_MAX;
    case 8: /* iteration end: begin a, optional separator b (not shown) */
      return pc != 0 && a != UINT16_MAX && c == UINT16_MAX;
    case 10: /* end */
      return pc != 0 && a == UINT16_MAX && b == UINT16_MAX && c == UINT16_MAX;
    default:
      return false;
  }
}

bool erc7730_cap_formatter(const Erc7730Formatter* formatter) {
  if (!formatter || formatter->flags != 0 ||
      formatter->argument_count > ERC7730_FORMATTER_MAX_ARGUMENTS)
    return false;
  uint32_t roles = 0;
  for (uint8_t i = 0; i < formatter->argument_count; i++) {
    const Erc7730FormatterArgument* argument = &formatter->arguments[i];
    if (argument->source > 7 ||
        (erc7730_cap_argument_sources(formatter->kind, argument->role) &
         ERC7730_CAP_BIT(argument->source)) == 0 ||
        (roles & ERC7730_CAP_BIT(argument->role)) != 0)
      return false;
    roles |= ERC7730_CAP_BIT(argument->role);
  }
  const uint32_t required =
      erc7730_cap_formatter_required_roles(formatter->kind);
  return required != 0 && (roles & required) == required;
}

bool erc7730_cap_path(const Erc7730Path* path) {
  if (!path || path->source > 7 ||
      (ERC7730_CAP_PATH_SOURCES & ERC7730_CAP_BIT(path->source)) == 0)
    return false;
  if (path->source == 2) /* a container: no steps */
    return path->step_count == 0 && path->source_index <= 31 &&
           (ERC7730_CAP_CONTAINERS & ERC7730_CAP_BIT(path->source_index)) != 0;
  if (path->source == 3) /* a literal: no steps */
    return path->step_count == 0 && path->source_index != UINT16_MAX;
  if (path->step_count == 0 || path->step_count >= ERC7730_ABI_MAX_DEPTH)
    return false;
  for (uint8_t i = 0; i < path->step_count; i++) {
    if (path->steps[i].opcode > 31 ||
        (ERC7730_CAP_PATH_STEP_OPCODES &
         ERC7730_CAP_BIT(path->steps[i].opcode)) == 0)
      return false;
  }
  return true;
}

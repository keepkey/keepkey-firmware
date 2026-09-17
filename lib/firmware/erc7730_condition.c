#include "keepkey/firmware/erc7730_condition.h"

#include <string.h>

static bool all_zero(const uint8_t* value, size_t length) {
  uint8_t combined = 0;
  for (size_t i = 0; i < length; i++) combined |= value[i];
  return combined == 0;
}

static bool capture_empty(const Erc7730AbiProgram* program,
                          const Erc7730AbiCapture* capture, bool* empty) {
  if (!program || !capture || !empty || capture->node >= program->node_count)
    return false;
  const Erc7730AbiNode* node = &program->nodes[capture->node];
  switch (node->kind) {
    case ERC7730_ABI_UINT:
    case ERC7730_ABI_INT:
    case ERC7730_ABI_ADDRESS:
    case ERC7730_ABI_BOOL:
      if (capture->length != 32) return false;
      *empty = all_zero(capture->data, capture->length);
      return true;
    case ERC7730_ABI_FIXED_BYTES:
      if (capture->length != 32 || node->size == 0 || node->size > 32)
        return false;
      *empty = all_zero(capture->data, node->size);
      return true;
    case ERC7730_ABI_BYTES:
    case ERC7730_ABI_STRING:
      *empty = capture->length == 0;
      return true;
    default:
      return false;
  }
}

bool erc7730_condition_evaluate_basic(const Erc7730Condition* condition,
                                      const Erc7730AbiProgram* program,
                                      const Erc7730AbiCapture* capture,
                                      bool* visible) {
  if (!condition || !visible || condition->flags != 0) return false;
  if (condition->opcode == 1 || condition->opcode == 3) {
    *visible = true;
    return condition->path == UINT16_MAX &&
           condition->literal_set == UINT16_MAX;
  }
  if (condition->opcode == 2) {
    *visible = false;
    return condition->path == UINT16_MAX &&
           condition->literal_set == UINT16_MAX;
  }
  if (condition->opcode == 4 || condition->opcode == 5) {
    bool empty = false;
    if (condition->path == UINT16_MAX || condition->literal_set != UINT16_MAX ||
        !capture_empty(program, capture, &empty))
      return false;
    *visible = condition->opcode == 4 ? empty : !empty;
    return true;
  }
  return false;
}

static void canonical_unsigned(const uint8_t* value, size_t length,
                               const uint8_t** canonical,
                               size_t* canonical_length) {
  size_t offset = 0;
  while (offset + 1u < length && value[offset] == 0) offset++;
  *canonical = value + offset;
  *canonical_length = length - offset;
}

bool erc7730_capture_equals_literal(const Erc7730AbiProgram* program,
                                    const Erc7730AbiCapture* capture,
                                    const Erc7730Literal* literal) {
  if (!program || !capture || !literal || capture->node >= program->node_count)
    return false;
  const Erc7730AbiNode* node = &program->nodes[capture->node];
  const uint8_t* value = capture->data;
  size_t length = capture->length;
  if (literal->kind == 1 && node->kind == ERC7730_ABI_UINT && length == 32) {
    canonical_unsigned(value, length, &value, &length);
  } else if (literal->kind == 3 && node->kind == ERC7730_ABI_FIXED_BYTES &&
             length == 32) {
    length = node->size;
  } else if (literal->kind == 3 && node->kind == ERC7730_ABI_BYTES) {
    /* payload is already canonical */
  } else if (literal->kind == 5 && node->kind == ERC7730_ABI_ADDRESS &&
             length == 32) {
    value += 12;
    length = 20;
  } else if (literal->kind == 6 && node->kind == ERC7730_ABI_BOOL &&
             length == 32) {
    value += 31;
    length = 1;
  } else {
    return false;
  }
  return length == literal->length &&
         (length == 0 || memcmp(value, literal->value, length) == 0);
}

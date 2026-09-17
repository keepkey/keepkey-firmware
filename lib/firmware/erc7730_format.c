#include "keepkey/firmware/erc7730_format.h"

#include <string.h>

#include "memzero.h"

static char hex_digit(uint8_t value) {
  return value < 10 ? (char)('0' + value) : (char)('a' + value - 10);
}

static bool format_hex(const uint8_t* data, size_t length, char* output,
                       size_t output_size) {
  if (!data || !output || length > (SIZE_MAX - 3u) / 2u ||
      output_size < 2u + 2u * length + 1u)
    return false;
  output[0] = '0';
  output[1] = 'x';
  for (size_t i = 0; i < length; i++) {
    output[2 + 2 * i] = hex_digit(data[i] >> 4);
    output[3 + 2 * i] = hex_digit(data[i] & 0x0f);
  }
  output[2 + 2 * length] = '\0';
  return true;
}

static bool format_unsigned(const uint8_t value[32], bool negative,
                            char* output, size_t output_size) {
  uint8_t magnitude[32];
  memcpy(magnitude, value, sizeof(magnitude));
  if (negative) {
    uint16_t carry = 1;
    for (size_t i = sizeof(magnitude); i > 0; i--) {
      const uint16_t converted = (uint16_t)(magnitude[i - 1] ^ 0xffu) + carry;
      magnitude[i - 1] = (uint8_t)converted;
      carry = converted >> 8;
    }
  }

  char reversed[78];
  size_t digits = 0;
  bool nonzero = false;
  for (size_t i = 0; i < sizeof(magnitude); i++) nonzero |= magnitude[i] != 0;
  while (nonzero) {
    uint16_t remainder = 0;
    nonzero = false;
    for (size_t i = 0; i < sizeof(magnitude); i++) {
      const uint16_t current = (uint16_t)(remainder * 256u + magnitude[i]);
      magnitude[i] = (uint8_t)(current / 10u);
      remainder = current % 10u;
      nonzero |= magnitude[i] != 0;
    }
    if (digits >= sizeof(reversed)) {
      memzero(magnitude, sizeof(magnitude));
      return false;
    }
    reversed[digits++] = (char)('0' + remainder);
  }
  if (digits == 0) reversed[digits++] = '0';
  const size_t prefix = negative ? 1u : 0u;
  if (output_size < prefix + digits + 1u) {
    memzero(magnitude, sizeof(magnitude));
    return false;
  }
  if (negative) output[0] = '-';
  for (size_t i = 0; i < digits; i++)
    output[prefix + i] = reversed[digits - i - 1u];
  output[prefix + digits] = '\0';
  memzero(magnitude, sizeof(magnitude));
  memzero(reversed, sizeof(reversed));
  return true;
}

bool erc7730_format_raw(const Erc7730AbiProgram* program,
                        const Erc7730AbiCapture* capture, char* output,
                        size_t output_size) {
  if (!program || !capture || !output || output_size == 0 ||
      capture->node >= program->node_count) {
    if (output && output_size != 0) output[0] = '\0';
    return false;
  }
  output[0] = '\0';
  const Erc7730AbiNode* node = &program->nodes[capture->node];
  if (node->kind == ERC7730_ABI_UINT || node->kind == ERC7730_ABI_INT) {
    if (capture->length != 32) return false;
    return format_unsigned(
        capture->data,
        node->kind == ERC7730_ABI_INT && (capture->data[0] & 0x80u) != 0,
        output, output_size);
  }
  if (node->kind == ERC7730_ABI_ADDRESS) {
    if (capture->length != 32) return false;
    return format_hex(capture->data + 12, 20, output, output_size);
  }
  if (node->kind == ERC7730_ABI_BOOL) {
    if (capture->length != 32 || capture->data[31] > 1) return false;
    const char* value = capture->data[31] ? "true" : "false";
    if (output_size <= strlen(value)) return false;
    strcpy(output, value);
    return true;
  }
  if (node->kind == ERC7730_ABI_FIXED_BYTES) {
    if (capture->length != 32 || node->size == 0 || node->size > 32)
      return false;
    return format_hex(capture->data, node->size, output, output_size);
  }
  if (node->kind == ERC7730_ABI_BYTES)
    return format_hex(capture->data, capture->length, output, output_size);
  if (node->kind == ERC7730_ABI_STRING) {
    if (capture->length >= output_size) return false;
    memcpy(output, capture->data, capture->length);
    output[capture->length] = '\0';
    return true;
  }
  return false;
}

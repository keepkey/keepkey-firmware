#include "keepkey/firmware/erc7730_format.h"

#include <string.h>

#include "trezor/crypto/address.h"
#include "trezor/crypto/bignum.h"
#include "trezor/crypto/memzero.h"

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

bool erc7730_format_integer(const uint8_t value[32], bool negative,
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
  bignum256 number;
  bn_read_be(magnitude, &number);
  const size_t written = bn_format(&number, negative ? "-" : NULL, NULL, 0, 0,
                                   false, output, output_size);
  memzero(magnitude, sizeof(magnitude));
  memzero(&number, sizeof(number));
  return written != 0;
}

bool erc7730_format_text(const uint8_t* bytes, size_t length, char* output,
                         size_t output_size) {
  if (!output || output_size == 0) return false;
  output[0] = '\0';
  if (!bytes && length != 0) return false;
  size_t written = 0;
  for (size_t i = 0; i < length; i++) {
    const uint8_t byte = bytes[i];
    const bool plain_space = byte == ' ' && i != 0 && i + 1u != length &&
                             bytes[i - 1u] != ' ' && bytes[i + 1u] != ' ';
    size_t needed = 1;
    if (byte == '\\') {
      needed = 2;
    } else if (byte < 0x20 || byte >= 0x7f || (byte == ' ' && !plain_space)) {
      needed = 4;
    }
    if (output_size - written <= needed) {
      output[0] = '\0';
      return false;
    }
    if (needed == 1u) {
      output[written++] = (char)byte;
    } else if (needed == 2u) {
      output[written++] = '\\';
      output[written++] = '\\';
    } else {
      output[written++] = '\\';
      output[written++] = 'x';
      output[written++] = hex_digit(byte >> 4);
      output[written++] = hex_digit(byte & 0x0f);
    }
  }
  output[written] = '\0';
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
    return erc7730_format_integer(
        capture->data,
        node->kind == ERC7730_ABI_INT && (capture->data[0] & 0x80u) != 0,
        output, output_size);
  }
  if (node->kind == ERC7730_ABI_ADDRESS) {
    if (capture->length != 32 || output_size < 43u) return false;
    output[0] = '0';
    output[1] = 'x';
    ethereum_address_checksum(capture->data + 12, output + 2, false, 0);
    return true;
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
  if (node->kind == ERC7730_ABI_STRING)
    return erc7730_format_text(capture->data, capture->length, output,
                               output_size);
  return false;
}

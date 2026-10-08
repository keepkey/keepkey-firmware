#include "keepkey/firmware/erc7730_format.h"

#include <string.h>

#include "trezor/crypto/address.h"
#include "trezor/crypto/memzero.h"

static char hex_digit(uint8_t value) {
  return value < 10 ? (char)('0' + value) : (char)('a' + value - 10);
}

bool erc7730_format_text(const uint8_t* bytes, size_t length, char* output,
                         size_t output_size) {
  if (!output || output_size == 0) return false;
  output[0] = '\0';
  if (!bytes && length != 0) return false;
  size_t written = 0;
  for (size_t i = 0; i < length; i++) {
    const uint8_t byte = bytes[i];
    size_t needed = 1;
    if (byte == '\\') {
      needed = 2;
    } else if (byte <= 0x20 || byte >= 0x7f) {
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

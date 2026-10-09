#include "keepkey/firmware/erc7730_field.h"

#include "keepkey/firmware/erc7730_format.h"

#include <stdio.h>
#include <string.h>

#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "trezor/crypto/address.h"
#include "trezor/crypto/bignum.h"
#include "trezor/crypto/memzero.h"

bool erc7730_format_address(const uint8_t address[20], bool this_wallet,
                            char* output, size_t output_size) {
  const char* suffix = this_wallet ? "\n(this wallet)" : "";
  if (!address || !output || output_size < 43u + strlen(suffix)) {
    if (output && output_size) output[0] = '\0';
    return false;
  }
  output[0] = '0';
  output[1] = 'x';
  ethereum_address_checksum(address, output + 2, false, 0);
  strlcpy(output + 42, suffix, output_size - 42u);
  return true;
}

bool erc7730_format_token_amount(const uint8_t amount[32],
                                 const uint8_t token[20], bool native,
                                 uint64_t chain_id, const char* message,
                                 char* output, size_t output_size) {
  if (!amount || !token || !output || output_size == 0) return false;
  output[0] = '\0';
  static const uint8_t zero[20] = {0};
  const TokenType* known = NULL;
  if (chain_id <= UINT32_MAX && memcmp(token, zero, 20) != 0) {
    known = tokenByChainAddress((uint32_t)chain_id, token);
    if (known == UnknownToken) known = NULL;
  }
  /* A signer alias never overrides the firmware token table. */
  if (known) native = false;

  char value[160]; /* 78 digits + "\nunknown token\n0x" + 40 */
  bool ok;
  if (native || known) {
    bignum256 amnt;
    bn_read_be(amount, &amnt);
    /* Same rendering as the ordinary Ethereum review. */
    ok = chain_id <= UINT32_MAX &&
         (native ? ethereumFormatNativeAmount(&amnt, (uint32_t)chain_id, value,
                                              sizeof(value))
                 : ethereumFormatAmount(&amnt, known, (uint32_t)chain_id, value,
                                        sizeof(value)));
    memzero(&amnt, sizeof(amnt));
    if (ok && native) {
      char checksummed[41], disclosed[160];
      ethereum_address_checksum(token, checksummed, false, 0);
      const int length =
          snprintf(disclosed, sizeof(disclosed),
                   "Signer native alias:\n0x%s\n%s", checksummed, value);
      ok = length > 0 && (size_t)length < sizeof(disclosed);
      if (ok) memcpy(value, disclosed, (size_t)length + 1u);
      memzero(disclosed, sizeof(disclosed));
    }
  } else {
    char digits[80], checksummed[41];
    ethereum_address_checksum(token, checksummed, false, 0);
    ok = erc7730_format_integer(amount, false, digits, sizeof(digits)) &&
         (size_t)snprintf(value, sizeof(value), "%s\nunknown token\n0x%s",
                          digits, checksummed) < sizeof(value);
    memzero(digits, sizeof(digits));
  }
  if (ok) {
    const int length =
        /* The threshold message is the signer's; it sits above the value
         * and is marked as theirs. */
        message
            ? snprintf(output, output_size, "Signer: %s\n%s", message, value)
            : snprintf(output, output_size, "%s", value);
    ok = length > 0 && (size_t)length < output_size;
  }
  if (!ok) output[0] = '\0';
  memzero(value, sizeof(value));
  return ok;
}

bool erc7730_format_native_amount(const uint8_t amount[32], uint64_t chain_id,
                                  char* output, size_t output_size) {
  if (!amount || !output || output_size == 0 || chain_id > UINT32_MAX)
    return false;
  bignum256 value;
  bn_read_be(amount, &value);
  const bool ok = ethereumFormatNativeAmount(&value, (uint32_t)chain_id, output,
                                             (int)output_size);
  memzero(&value, sizeof(value));
  if (!ok) output[0] = '\0';
  return ok;
}

bool erc7730_format_nft(const uint8_t token_id[32],
                        const uint8_t collection[20], char* output,
                        size_t output_size) {
  char id[80], address[43];
  const bool ok =
      token_id && collection && output && output_size &&
      erc7730_format_integer(token_id, false, id, sizeof(id)) &&
      erc7730_format_address(collection, false, address, sizeof(address)) &&
      (size_t)snprintf(output, output_size, "Token ID %s\nCollection\n%s", id,
                       address) < output_size;
  if (!ok && output && output_size) output[0] = '\0';
  memzero(id, sizeof(id));
  return ok;
}

/* The value as a uint64, when it fits. */
static bool word_u64(const uint8_t value[32], uint64_t* out) {
  for (size_t i = 0; i < 24; i++)
    if (value[i] != 0) return false;
  uint64_t v = 0;
  for (size_t i = 24; i < 32; i++) v = (v << 8) | value[i];
  *out = v;
  return true;
}

bool erc7730_format_date(const uint8_t value[32], bool block_height,
                         char* output, size_t output_size) {
  char raw[80];
  if (!value || !output || output_size == 0 ||
      !erc7730_format_integer(value, false, raw, sizeof(raw)))
    return false;
  int length;
  uint64_t seconds;
  /* 253402300799 is 9999-12-31 23:59:59 UTC. */
  if (block_height) {
    length = snprintf(output, output_size, "Block %s", raw);
  } else if (!word_u64(value, &seconds) || seconds > UINT64_C(253402300799)) {
    length = snprintf(output, output_size, "%s\n(not a date)", raw);
  } else {
    /* Hinnant civil_from_days, exact over this range. */
    const uint64_t days = seconds / 86400u, rest = seconds % 86400u;
    const uint64_t z = days + 719468u, era = z / 146097u;
    const uint64_t doe = z - era * 146097u;
    const uint64_t yoe =
        (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
    const uint64_t doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
    const uint64_t mp = (5u * doy + 2u) / 153u;
    const unsigned day = (unsigned)(doy - (153u * mp + 2u) / 5u + 1u);
    const unsigned month = (unsigned)(mp < 10u ? mp + 3u : mp - 9u);
    const unsigned year =
        (unsigned)(yoe + era * 400u + (month <= 2u ? 1u : 0u));
    length =
        snprintf(output, output_size, "%04u-%02u-%02u %02u:%02u:%02u UTC\n(%s)",
                 year, month, day, (unsigned)(rest / 3600u),
                 (unsigned)(rest / 60u % 60u), (unsigned)(rest % 60u), raw);
  }
  memzero(raw, sizeof(raw));
  if (length < 0 || (size_t)length >= output_size) {
    output[0] = '\0';
    return false;
  }
  return true;
}

bool erc7730_format_duration(const uint8_t value[32], char* output,
                             size_t output_size) {
  char raw[80];
  if (!value || !output || output_size == 0 ||
      !erc7730_format_integer(value, false, raw, sizeof(raw)))
    return false;
  int length;
  uint64_t seconds;
  if (!word_u64(value, &seconds)) {
    length = snprintf(output, output_size, "%s s", raw);
  } else {
    char parts[64] = "";
    size_t used = 0;
    const uint64_t units[4] = {86400u, 3600u, 60u, 1u};
    const char names[4] = {'d', 'h', 'm', 's'};
    uint64_t rest = seconds;
    for (size_t i = 0; i < 4; i++) {
      const uint64_t count = rest / units[i];
      rest %= units[i];
      if (count == 0 && !(i == 3 && used == 0)) continue;
      used += (size_t)snprintf(parts + used, sizeof(parts) - used, "%s%llu%c",
                               used ? " " : "", (unsigned long long)count,
                               names[i]);
    }
    length = snprintf(output, output_size, "%s\n(%s s)", parts, raw);
  }
  memzero(raw, sizeof(raw));
  if (length < 0 || (size_t)length >= output_size) {
    output[0] = '\0';
    return false;
  }
  return true;
}

bool erc7730_format_unit(const uint8_t value[32], uint8_t decimals,
                         const char* base, char* output, size_t output_size) {
  if (!value || !base || !output || output_size == 0) return false;
  bignum256 amount;
  bn_read_be(value, &amount);
  /* scaled: up to 78 digits, '.', and up to 254 leading zeros (any uint8
   * decimals); the length check below also reserves room for " base". */
  char scaled[344], raw[80];
  bool ok = bn_format(&amount, NULL, NULL, decimals, 0, false, scaled,
                      sizeof(scaled)) != 0 &&
            strlen(scaled) + 1u + strlen(base) < sizeof(scaled) &&
            erc7730_format_integer(value, false, raw, sizeof(raw));
  memzero(&amount, sizeof(amount));
  if (ok) {
    const int length =
        /* Signer-supplied unit: mark it first (same page as the value) and
         * show the raw integer. */
        snprintf(output, output_size, "unit set by signer\n%s%s%s\nraw %s",
                 scaled, base[0] ? " " : "", base, raw);
    ok = length > 0 && (size_t)length < output_size;
  }
  if (!ok) output[0] = '\0';
  memzero(scaled, sizeof(scaled));
  memzero(raw, sizeof(raw));
  return ok;
}

bool erc7730_format_enum(const char* value, const char* label, char* output,
                         size_t output_size) {
  if (!value || !output || output_size == 0) return false;
  const int length =
      /* Signer's label: marked first, like a unit. */
      label ? snprintf(output, output_size, "label set by signer\n%s (%s)",
                       label, value)
            : snprintf(output, output_size, "%s (unmapped)", value);
  if (length < 0 || (size_t)length >= output_size) {
    output[0] = '\0';
    return false;
  }
  return true;
}

bool erc7730_format_embedded(const uint8_t callee[20], const uint8_t* selector,
                             size_t selector_length, uint32_t data_length,
                             const uint8_t* amount, uint64_t chain_id,
                             const uint8_t* spender, char* output,
                             size_t output_size) {
  if (!callee || !output || output_size == 0 ||
      (selector_length && !selector) || selector_length > 4)
    return false;
  output[0] = '\0';
  char to[43], function[24] = "", value[128] = "", as[64] = "";
  bool ok = erc7730_format_address(callee, false, to, sizeof(to));
  if (ok && selector_length == 4)
    ok = (size_t)snprintf(function, sizeof(function),
                          "\nFunction 0x%02x%02x%02x%02x", selector[0],
                          selector[1], selector[2],
                          selector[3]) < sizeof(function);
  if (ok && amount) {
    char native[100];
    ok = erc7730_format_native_amount(amount, chain_id, native,
                                      sizeof(native)) &&
         (size_t)snprintf(value, sizeof(value), "\nValue %s", native) <
             sizeof(value);
    memzero(native, sizeof(native));
  }
  if (ok && spender) {
    char address[43];
    ok = erc7730_format_address(spender, false, address, sizeof(address)) &&
         (size_t)snprintf(as, sizeof(as), "\nAs %s", address) < sizeof(as);
  }
  if (ok) {
    const int length =
        data_length == 0
            ? snprintf(output, output_size, "To %s\nNo data%s%s", to, value, as)
            : snprintf(output, output_size, "To %s%s\nData %lu bytes%s%s", to,
                       function, (unsigned long)data_length, value, as);
    ok = length > 0 && (size_t)length < output_size;
  }
  if (!ok) output[0] = '\0';
  memzero(value, sizeof(value));
  return ok;
}

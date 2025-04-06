extern "C" {
#include "keepkey/firmware/coins.h"
#include "keepkey/firmware/ripple.h"
#include "keepkey/firmware/ripple_base58.h"
#include "hwcrypto/crypto/hasher.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size != 33) return 0;

  uint8_t buff[64];
  memset(buff, 0, sizeof(buff));

  Hasher hasher;
  hasher_Init(&hasher, HASHER_SHA2_RIPEMD);
  hasher_Update(&hasher, data, 33);
  hasher_Final(&hasher, buff + 1);

  char address[56];
  if (!ripple_encode_check(buff, 21, HASHER_SHA2D, address, MAX_ADDR_SIZE))
    return 1;

  uint8_t addr_raw[MAX_ADDR_RAW_SIZE];
  memset(addr_raw, 0, sizeof(addr_raw));
  uint32_t addr_raw_len =
      ripple_decode_check(address, HASHER_SHA2D, addr_raw, MAX_ADDR_RAW_SIZE);
  if (addr_raw_len != 21) return 2;

  if (memcmp(buff, addr_raw, 21) != 0) return 3;

  return 0;
}

#ifndef KEEPKEY_TEST_STORAGE_CIPHER_PROBE_H
#define KEEPKEY_TEST_STORAGE_CIPHER_PROBE_H

#include <stdbool.h>

enum StorageCipherObservation {
  STORAGE_IV_WIPED = 1u << 0,
  STORAGE_CTX_WIPED = 1u << 1,
  STORAGE_CIPHER_CALLED = 1u << 2,
  STORAGE_ROUND_TRIP_OK = 1u << 3,
  STORAGE_CIPHER_CLEANUP_COMPLETE = STORAGE_IV_WIPED | STORAGE_CTX_WIPED |
                                    STORAGE_CIPHER_CALLED |
                                    STORAGE_ROUND_TRIP_OK
};

#ifdef __cplusplus
extern "C" {
#endif
unsigned storage_test_cipher_cleanup(bool migrate, bool encrypt);
#ifdef __cplusplus
}
#endif

#endif

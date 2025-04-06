#include "keepkey/board/memcmp_s.h"

#include "keepkey/rand/rng.h"
#include "hwcrypto/crypto/rand.h"
#include "hwcrypto/crypto/memzero.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define DECOY_COUNT 8

#ifndef EMULATOR
/// \brief Compare two memory regions for equality in constant time.
///
/// Note: Don't mark lhs/rhs as const, even though they are, as this forces the
/// compiler to assume the underlying fuction might have changed them.
int memcmp_cst(void *lhs, void *rhs, size_t len);
#else
#warning "memcmp_s is not guaranteed to be constant-time on this architecture"
#define memcmp_cst(lhs, rhs, len) memcmp((lhs), (rhs), (len))
#endif

void asc_fill(char *permute, size_t len);

#ifdef EMULATOR
void asc_fill(char *permute, size_t len) {
  for (size_t i = 0; i != len; i++) {
    permute[i] = i;
  }
}
#endif

int memcmp_s(const void *lhs, const void *rhs, size_t len) {
  if (len < 32 || len > 255) {
    // Setting the floor on length to 32 is a simple way to guarantee that
    // all the decoy buffers we end up will never compare equal with either
    // lhs/rhs, since the chances of randomly generating the same 32 byte
    // sequence twice is astronomically small... you're just as likely to
    // guess Satoshi's private keys.
    assert(false && "unsupported memcmp_s length");
    abort();
  }

  static uint8_t decoys[DECOY_COUNT][255];
  random_buffer(&decoys[0][0], sizeof(decoys));

  static void *permuted[DECOY_COUNT + 2];
  for (size_t i = 0; i != DECOY_COUNT; i++) {
    permuted[i] = &decoys[i];
  }
  permuted[DECOY_COUNT] = (void *)lhs;
  permuted[DECOY_COUNT + 1] = (void *)rhs;

  static uint8_t permute[DECOY_COUNT + 2];
  asc_fill((char *)permute, DECOY_COUNT + 2);
  random_permute_char((char *)permute, DECOY_COUNT + 2);

  // Compare every pair of buffers once, and count how many match. We should
  // get exactly one match from the comparison of lhs with rhs, assuming they
  // matched to begin with. Use the permutation array as a random indirection
  // so that an attacker measuring power draw can't know which pair of arrays
  // we're actually comparing at any given moment.

  //   d d d d l r
  // d   1 1 1 1 1
  // d     1 1 1 1
  // d       1 1 1
  // d         1 1
  // l           0

  int diffs = 0;
  for (size_t y = 0; y != DECOY_COUNT + 2 - 1; y++) {
    for (size_t x = y + 1; x != DECOY_COUNT + 2; x++) {
      diffs += !!memcmp_cst(permuted[permute[x]], permuted[permute[y]], len);
    }
  }

  memzero(&decoys[0][0], sizeof(decoys));
  memzero(permuted, sizeof(permuted));
  memzero(permute, sizeof(permute));

  return diffs != (DECOY_COUNT + 2 - 1) * (DECOY_COUNT + 2) / 2 - 1;
}

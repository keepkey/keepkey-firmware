#ifndef KEEPKEY_BOARD_MEMCMPS_H
#define KEEPKEY_BOARD_MEMCMPS_H

#include <stddef.h>

/// Compare two memory regions for equality in constant time.
/// \param lhs must be an array of at least `len` bytes
/// \param rhs must be an array of at least `len` bytes
/// \param len must be in [32, 255), otherwise behavior is undefined.
int memcmp_s(const void *lhs, const void *rhs, size_t len);

#endif

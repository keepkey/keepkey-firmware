#ifndef KEEPKEY_BOARD_MEMCMPS_H
#define KEEPKEY_BOARD_MEMCMPS_H

#ifndef EMULATOR
/// Compare two memory regions for equality in constant time.
int memcmp_s(const void *lhs, const void *rhs, size_t len);
#else
#  include <string.h>
#  warning "memcmp_s is not guaranteed to be constant-time on this architecture"
#  define memcmp_s(lhs, rhs, len) memcmp((lhs), (rhs), (len))
#endif

#endif

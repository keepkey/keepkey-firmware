#ifndef KEEPKEY_BOARD_BSD_COMPAT_H
#define KEEPKEY_BOARD_BSD_COMPAT_H

/* strlcpy/strlcat prototypes for glibc/MinGW emulator builds; force-included
 * (see CMakeLists.txt). Not used by the ARM build. */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t strlcpy(char *dst, const char *src, size_t siz);
size_t strlcat(char *dst, const char *src, size_t siz);

#ifdef __cplusplus
}
#endif

#endif /* KEEPKEY_BOARD_BSD_COMPAT_H */

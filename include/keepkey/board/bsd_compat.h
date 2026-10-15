#ifndef KEEPKEY_BOARD_BSD_COMPAT_H
#define KEEPKEY_BOARD_BSD_COMPAT_H

/* strlcpy/strlcat prototypes for glibc/MinGW emulator builds; force-included
 * (see CMakeLists.txt). Not used by the ARM build. */

#include <stddef.h>
#include <string.h>

#if defined(__cplusplus) && defined(__GLIBC__)
#define KEEPKEY_BSD_NOTHROW noexcept
#else
#define KEEPKEY_BSD_NOTHROW
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* glibc uses noexcept; musl and MinGW use plain C declarations. Include
 * string.h first so the libc identity and any native declarations are known. */
size_t(strlcpy)(char *dst, const char *src, size_t siz) KEEPKEY_BSD_NOTHROW;
size_t(strlcat)(char *dst, const char *src, size_t siz) KEEPKEY_BSD_NOTHROW;

#ifdef __cplusplus
}
#endif

#undef KEEPKEY_BSD_NOTHROW

#endif /* KEEPKEY_BOARD_BSD_COMPAT_H */

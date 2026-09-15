#ifndef KEEPKEY_BOARD_BSD_COMPAT_H
#define KEEPKEY_BOARD_BSD_COMPAT_H

/*
 * Declarations for BSD libc extensions that macOS/BSD expose via <string.h>
 * but glibc (Linux) and MinGW (Windows) do not. The emulator build compiles
 * lib/board/strlcpy.c + strlcat.c when the libc lacks the definitions
 * (KK_HAVE_STRLCPY / KK_HAVE_STRLCAT), so only the prototypes are missing.
 *
 * Force-included for non-Apple emulator builds (see CMakeLists.txt) so every
 * translation unit sees the prototypes without us having to chase down ~20
 * call sites — and without touching the real hardware (ARM) build at all.
 */

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

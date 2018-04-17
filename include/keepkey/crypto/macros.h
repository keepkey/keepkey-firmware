#ifndef __MACROS_H__
#define __MACROS_H__

#define MEMSET_BZERO(p,l)	memset((p), 0, (l))

#ifndef __clang__
#  define FALLTHROUGH __attribute__((fallthrough))
#else
#  define FALLTHROUGH do {} while (0)
#endif

#endif

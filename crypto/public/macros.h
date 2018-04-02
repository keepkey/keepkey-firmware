#ifndef __MACROS_H__
#define __MACROS_H__

extern void *(*const volatile memset_vp)(void *, int, size_t);
#define MEMSET_BZERO(p,l)	memset_vp((p), 0, (l))

#endif

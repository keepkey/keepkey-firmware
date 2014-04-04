#ifndef DIAG_H_
#define DIAG_H_

#include <stdio.h>
#include <cd_string.h>

#define LOG_ENABLED 1


/**
 * This file contains diagnost functions related to assertion and debugging.
 *
 * To enable and build in logging, #define LOG_ENABLED.  If LOG_ENABLED is not defined,
 * the logging capailibity will not be compiled in, reducing code size.
 */

#if LOG_ENABLED


namespace cd {
    extern const char LOG_PREAMBLE[];

    enum LOG_LEVEL {
        LOG_INFO = 0,
        LOG_WARNING,
        LOG_ERR,
        LOG_ASSERT = LOG_ERR
    };

    void platformDiag(int priority, const char *fmt, ...);
    void platformAssert(const char *fmt, ...);
};

#define PRINT(fmt, ...) (cd::platformDiag(LOG_INFO, fmt, ##__VA_ARGS__))

#define LOG(fmt,...) (cd::platformDiag(LOG_INFO, "%s:%s:%d " fmt, cd::LOG_PREAMBLE, cd::pathsep(__FILE__, 2), __LINE__, ##__VA_ARGS__))

#define Error(fmt, ...) \
    { \
        cd::platformDiag(cd::LOG_ERR, "%s:%s:%d " fmt, cd::LOG_PREAMBLE, cd::pathsep(__FILE__, 2), __LINE__, ##__VA_ARGS__); \
    }

#define Warn(fmt, ...) \
    { \
        cd::platformDiag(cd::LOG_WARNING, "%s:%s:%d " fmt, cd::LOG_PREAMBLE, cd::pathsep(__FILE__, 2), __LINE__, ##__VA_ARGS__); \
    }

#define Assert(fmt, ...) \
    { \
        cd::platformAssert("%s:%s:%d " fmt, cd::LOG_PREAMBLE, cd::pathsep(__FILE__, 2), __LINE__, ##__VA_ARGS__); \
    }

#define AssertIf(condition, fmt, ...) \
    if(condition) \
    { \
        cd::platformAssert("%s:%s:%d " fmt, cd::LOG_PREAMBLE, cd::pathsep(__FILE__, 2), __LINE__, ##__VA_ARGS__); \
    }

#define AssertIfNot(condition, fmt, ...) \
    if(!(condition)) \
    { \
        cd::platformAssert("%s:%s:%d " fmt, cd::LOG_PREAMBLE, cd::pathsep(__FILE__, 2), __LINE__, ##__VA_ARGS__); \
    }

#define AssertOnErrno(condition, fmt, ...) \
    if((condition) == -1) \
    { \
        cd::platformAssert("%s:%s:%d " fmt, cd::LOG_PREAMBLE, cd::pathsep(__FILE__, 2), __LINE__, ##__VA_ARGS__); \
        perror("errno description"); \
    }

#define Abort(ret, fmt, ...) \
    { \
        cd::platformDiag(cd::LOG_ERR, "%s:%s:%d " fmt, cd::LOG_PREAMBLE, cd::pathsep(__FILE__, 2), __LINE__, ##__VA_ARGS__); \
        return ret; \
    }

#define AbortIf(condition, ret, fmt, ...) \
    if (condition) \
    { \
        cd::platformDiag(cd::LOG_ERR, "%s:%s:%d " fmt, cd::LOG_PREAMBLE, cd::pathsep(__FILE__, 2), __LINE__, ##__VA_ARGS__); \
        return ret; \
    }
#define AbortIfNot(condition, ret, fmt, ...) \
    if(!(condition)) \
    { \
        cd::platformDiag(cd::LOG_ERR, "%s:%s:%d " fmt, cd::LOG_PREAMBLE, cd::pathsep(__FILE__, 2), __LINE__, ##__VA_ARGS__); \
        return ret; \
    }

#define AbortOnErrno(condition, ret, fmt, ...) \
    if((condition) == -1) \
    { \
        cd::platformDiag(cd::LOG_ERR, "%s:%s:%d " fmt, cd::LOG_PREAMBLE, cd::pathsep(__FILE__, 2), __LINE__, ##__VA_ARGS__); \
        perror("errno description"); \
        return ret; \
    }

#else
    #define LOG(fmt,...)
#endif

#endif /* ASSERT_H_ */

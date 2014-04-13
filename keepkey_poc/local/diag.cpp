/**
  * @file
  *
  * @author Thomas Taranowski
  *
  * @brief Diagnostic print routines.
  *
  */

#include <stdarg.h>
#include <stdio.h>

#include "diag.h"

namespace cd 
{

    /* 
     * Generic log preamble for prefixing log messages.
     */
    const char LOG_PREAMBLE[] = "";

    /**
     * Standard diagnostic print routine. 
     *
     * @param fmt Printf-style format string
     * @param va-args printf-style variable length argument list.
     */
    void platformDiag(int priority, const char *fmt, ...)
    {

        va_list vl;
        va_start(vl, fmt);

        vfprintf(stdout, fmt, vl);
        fflush(stdout);

        va_end(vl);
    }

    /**
     * platform specific assert routine;
     *
     * @param fmt Printf-style format string
     * @param va-args printf-style variable length argument list.
     */
    void platformAssert(const char *fmt, ...) {
        va_list vl;
        va_start(vl, fmt);
        vfprintf(stdout, fmt, vl);
        fflush(stdout);

        while(1) {}

        va_end(vl);
    }
};

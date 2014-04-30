/******************************************************************************
    Author: Lowell Skoog, Carbon Design Group

    Copyright (c) 2011, Carbon Design Group
    All rights reserved.

    Redistribution and use in source and binary forms, with or without        
    modification, are permitted provided that the following conditions are    
    met:                                                                      

    * Redistributions of source code must retain the above copyright notice,  
      this list of conditions and the following disclaimer.                     

    * Redistributions in binary form must reproduce the above copyright       
      notice, this list of conditions and the following disclaimer in the     
      documentation and/or other materials provided with the distribution.    

    * Neither the name of the Carbon Design Group nor the names of its        
      contributors may be used to endorse or promote products derived from    
      this software without specific prior written permission.                

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS       
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT         
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR     
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT      
    HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,    
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED  
    TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR    
    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF    
    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING      
    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS        
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.              

******************************************************************************/

/// @file carbon.h
/// Standard System-Wide Definitions

/// @page CarbonH Standard System-Wide Definitions (carbon.h)
///
/// This file contains standard system-wide definitions such as:
///
/// * Bitwise operations
/// * Numeric operations
/// * Miscellaneous macros

#ifndef __CARBON_H
#define __CARBON_H

#ifdef __cplusplus
extern "C" {
#endif


//=============================== INCLUDES ====================================

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined (__AVR_ARCH__) // WINAVR platform
#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#endif

//=============================== CONSTANTS ===================================

// Formal version ID of the CDLIB package.
#define CDLIB_VERSION "1.0"

/// TRUE and FALSE.
/// @todo (LS) Either eliminate USE_CDLIB_TRUE_FALSE or document it!
#ifdef USE_CDLIB_TRUE_FALSE
#ifndef FALSE
#define FALSE (0)
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif
#endif // 0

/// ON and OFF. Synonymous with TRUE and FALSE.
#ifndef ON
#define ON TRUE
#endif
#ifndef OFF
#define OFF FALSE
#endif

/// NULL pointer value.
#ifndef NULL
#ifdef __cplusplus
#define NULL 0
#else
#define NULL ((void *)0)
#endif
#endif

//================================= TYPES =====================================

//========================== BITWISE OPERATIONS ===============================

/// Bit operations (where bit(s) expressed using mask).
#define SETBIT(var,mask) ((var) |=  (mask))             // Set bit(s)
#define CLRBIT(var,mask) ((var) &= ~(mask))             // Clear bit(s)
#define FLPBIT(var,mask) ((var) =  ((mask)^(var)))      // Flip (invert) bit(s)
#define TSTBIT(var,mask) ((var) &   (mask))             // Test value of bit(s)

/// Bit operations (where bit is expressed as a shift index).
#define SETBITX(var,bit)  ((var) |=  (1<<bit))          // Set bit
#define CLRBITX(var,bit)  ((var) &= ~(1<<bit))          // Clear bit
#define FLPBITX(var,bit)  ((var) =  ((1<<bit)^(var)))   // Flip (invert) bit
#define TSTBITX(var,bit)  ((var) &   (1<<bit))          // Test value of bit

/// The upper 8 bits of a 16-bit value.
#define MSB(a) ((a & 0xFF00) >> 8)

/// The lower 8 bits of a 16-bit value.
#define LSB(a) ((a & 0xFF))

/// Swap upper and lower bytes in a 16-bit value.
#define SWAP_BYTES(x) ((((x)&0xFF)<<8)|(((x)>>8)&0xFF))

/// Write value as field of bits within a register. Leave other bits unchanged.
#define WRBITS(reg,mask,val) \
    do { \
        UINT8 _r = reg; \
        CLRBIT(_r,mask); \
        SETBIT(_r,val); \
        reg = _r; \
    } while(0)

/// Read variable from field of bits within a register.
#define RDBITS(reg,mask,var) \
    do { \
        var = reg; \
        CLRBIT(var,~(mask)); \
    } while(0)

//========================== NUMERIC OPERATIONS ===============================

/// Finds the minimum of two arguments.
#define MIN(x,y) (((x) < (y)) ? (x) : (y))

/// Finds the maximum of two arguments.
#define MAX(x,y) (((x) > (y)) ? (x) : (y))

/// Finds absolute value of the argument.
#define ABS(value) (((value) > 0) ? (value) : (-(value)))

/// Limit argument between min/max values.
#define LIMIT(value, minValue, maxValue) \
    (((value) > (maxValue)) ? (maxValue) : (((value) < (minValue)) ? (minValue) : (value)))

/// Integer division with rounding.
//
// Rounding the result means add half a unit and truncate.
// Do this with integer math by adding half a denomintor before dividing.
// If the answer is negative, you need to subtract half a unit.
#define DIVIDE_ROUND(NUM, DENOM) \
    (((((NUM) > 0) && ((DENOM) > 0)) || (((NUM) < 0) && ((DENOM) < 0))) \
    ? (((NUM) + ((DENOM) >> 1)) / (DENOM)) \
    : (((NUM) - ((DENOM) >> 1)) / (DENOM)))

/// Same thing for unsigned numbers (avoids pointless compares to zero).
#define DIVIDE_ROUND_UNS(NUM, DENOM) \
    (((NUM) + ((DENOM) >> 1)) / (DENOM))

/// Verify that a number is even.
#define IS_EVEN(val) ((val % 2) == 0)

//-----------------------------------------------------------------------------
/// @brief Verify that a value is between two other values.
//-----------------------------------------------------------------------------
#define BETWEEN(val,min,max) \
        ( ( min <= val ) && ( val <= max ) )


/// Interpolation.
#define INTERPOLATE(IN_VALUE, IN_MIN, IN_MAX, OUT_MIN, OUT_MAX) \
    ((OUT_MIN) + DIVIDE_ROUND((((IN_VALUE) - (IN_MIN)) * ((OUT_MAX) - (OUT_MIN))), ((IN_MAX) - (IN_MIN))))

/// How close do floating point values have to be to compare equal?
//
// We use an 'epsilon' value to specify how close two floating point
// values must be before we declare them to be equal.
#define EPSILON 1.0e-15

/** Macros for comparing floating point numbers.

    Requires inclusion of math.h.

    <pre>

    <------------->|---------x---------|<---------------->
        REGION 1   |     REGION 2      |   REGION 3                  
          LT       |     EQUAL         |   GT
                   |                   |                             
                   x-epsilon           x+epsilon

     y in REGION    MACROS EVALUATE TRUE
     -----------    --------------------
     1              FLOATING_POINT_LT(x,y)
                    FLOATING_POINT_LE(x,y)

     2              FLOATING_POINT_EQ(x,y)
                    FLOATING_POINT_LE(x,y)
                    FLOATING_POINT_GE(x,y)
 
     3              FLOATING_POINT_GT(x,y)
                    FLOATING_POINT_GE(x,y)

    </pre>
*/
#define FLOATING_POINT_EQ_WITHIN(x, y, epsilon) (fabs(x - y) <= epsilon)
#define FLOATING_POINT_EQ(x, y) FLOATING_POINT_EQ_WITHIN(x, y, EPSILON)
#define FLOATING_POINT_LT(x,y) (((x) + EPSILON) < y)
#define FLOATING_POINT_GT(x,y) (((y) + EPSILON) < x)
#define FLOATING_POINT_LE(x,y) \
    (FLOATING_POINT_LT(x,y) || FLOATING_POINT_EQ(x,y))
#define FLOATING_POINT_GE(x,y) \
    (FLOATING_POINT_GT(x,y) || FLOATING_POINT_EQ(x,y))


//-----------------------------------------------------------------------------
// Given a type and two values, swap them.
#define SWAP( type, value1, value2 )\
    do {\
        type temp_value = (value1);\
        (value1) = (value2);\
        (value2) = temp_value;\
    } while(0)


//========================== MISCELLANEOUS MACROS =============================

/// Loop forever.
#define FOREVER while(1)        

/// Array length independent of element size.
#define ARRAY_LENGTH(array) (sizeof(array)/sizeof(array[0]))

/// Test whether a pointer to elements in a array is still within bounds.
#define PTR_IN_ARRAY(ptr,array) \
    (&array[0] <= ptr && ptr < &array[ARRAY_LENGTH(array)])

/** This macro is for use by other macros to form a fully valid C statement.
    Without this, if/else conditionals could show unexpected behavior.

    @code
    For example, use...
      #define SET_REGS()    st( ioreg1 = 0; ioreg2 = 0; )
    instead of ...
      #define SET_REGS()    { ioreg1 = 0; ioreg2 = 0; }
    or
      #define  SET_REGS()   ioreg1 = 0; ioreg2 = 0;
    @endcode

    The last macro above would not behave as expected in the if/else          
    construct.  The second to last macro will cause a compiler error in       
    certain uses of if/else construct.                                        

    It is not necessary, or recommended, to use this macro where there is     
    already a valid C statement.                                              

    @code
    For example, the following is redundant...
      #define CALL_FUNC()   st(  func();  )
    This should simply be...
      #define CALL_FUNC()   func()
    @endcode

    The while condition in this macro evaluates false without generating a
    constant-controlling-loop type of warning on most compilers.
*/
#define st(x)      do { x } while (__LINE__ == -1)


#ifdef __cplusplus
}
#endif

#endif // __CARBON_H


/**
 * Copyright (c) 2016 Jochen Hoenicke
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __CURVES_H__
#define __CURVES_H__

#define SECP256K1_STRING "secp256k1"
#define NIST256P1_STRING "nist256p1"
#define ED25519_STRING  "ed25519"
#define CURVE25519_STRING "curve25519"


extern const char SECP256K1_NAME[];
extern const char NIST256P1_NAME[];
extern const char ED25519_NAME[];
extern const char CURVE25519_NAME[];

/* === Unions ===============================================================*/

typedef union 
{
    char secp256k1[sizeof(SECP256K1_STRING)];
    char nist256p1[sizeof(NIST256P1_STRING)];
    char ed25519[sizeof(ED25519_STRING)];
    char curve25519[sizeof(CURVE25519_STRING)];
}ecdsa_curve_type_;
#endif

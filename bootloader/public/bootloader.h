/* START KEEPKEY LICENSE */
/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2014 KeepKey LLC
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/* END KEEPKEY LICENSE */

/* prevent duplicate inclusion */
#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#ifdef __cplusplus
extern "C" {
#endif

/* definitions */
#define PUBKEYS 5
#define PUBKEY_LENGTH 65 
#define SIGNATURES 3

/* extern declarations */
extern int signatures_ok(void);

/* typedefs */
typedef struct
{
    uint32_t magic;
    uint32_t code_len;
    uint8_t  sig_index1;
    uint8_t  sig_index2;
    uint8_t  sig_index3;
    uint8_t  flag;
    uint8_t  rsv[52];
    uint8_t  sig1[64];
    uint8_t  sig2[64];
    uint8_t  sig3[64];
}app_meta_td;

#ifdef __cplusplus
}
#endif
#endif

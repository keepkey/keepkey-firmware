/* START KEEPKEY LICENSE */
/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2014 Carbon Design Group <tom@carbondesign.com>
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

#ifndef UUID_H
#define UUID_H

#include <stdint.h>

/**
 * 96 bit Arm UUID.
 */
#define SIZEOF_UUID 12

/**
 * This is 2 char's per byte + the 1 byte NULL at the end.
 */
#define SIZEOF_UUID_STRLEN (SIZEOF_UUID*2 +1)

typedef struct
{
    union
    {
        uint8_t  bytes[SIZEOF_UUID];
        uint32_t words[SIZEOF_UUID / 4];
    } u;
} ArmUuid;

/**
 * Refer to section 33 of the stm32f2 reference manual.
 */
#define ARM_UUID ( (const ArmUuid const *)0x1fff7a10 )

/**
 * @return A human-readable string representation of the UUID.  This
 *	   returns a pointer to a static buffer, so it's safe to reference
 *	   the returned value for the life of the program.
 */
const char* get_uuid_str();

#endif

/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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
 */

/* === Includes ============================================================ */

#include <libopencm3/cm3/scb.h>

#include "util.h"

/* === Private Variables =================================================== */

static const char *hexdigits = "0123456789ABCDEF";

/* === Functions =========================================================== */

void uint32hex(uint32_t num, char *str)
{
	uint32_t i;
	for (i = 0; i < 8; i++) {
		str[i] = hexdigits[(num >> (28 - i * 4)) & 0xF];
	}
}

// converts data to hexa
void data2hex(const void *data, uint32_t len, char *str)
{
	uint32_t i;
	const uint8_t *cdata = (uint8_t *)data;
	for (i = 0; i < len; i++) {
		str[i * 2    ] = hexdigits[(cdata[i] >> 4) & 0xF];
		str[i * 2 + 1] = hexdigits[cdata[i] & 0xF];
	}
	str[len * 2] = 0;
}

uint32_t readprotobufint(uint8_t **ptr)
{
	uint32_t result = (**ptr & 0x7F);
	if (**ptr & 0x80) {
		(*ptr)++;
		result += (**ptr & 0x7F) * 128;
		if (**ptr & 0x80) {
			(*ptr)++;
			result += (**ptr & 0x7F) * 128 * 128;
			if (**ptr & 0x80) {
				(*ptr)++;
				result += (**ptr & 0x7F) * 128 * 128 * 128;
				if (**ptr & 0x80) {
					(*ptr)++;
					result += (**ptr & 0x7F) * 128 * 128 * 128 * 128;
				}
			}
		}
	}
	(*ptr)++;
	return result;
}

void rev_byte_order(uint8_t *bfr, size_t len)
{
    size_t i;
    uint8_t tempdata; 

    for(i = 0; i < len/2; i++)
    {
        tempdata = bfr[i];
        bfr[i] = bfr[len - i - 1];
        bfr[len - i - 1] = tempdata;
    }
}

/*convert 64bit decimal to string (itoa)*/
void dec64_to_str(uint64_t dec64_val, char *str)
{
    unsigned int b = 0;
    static char *sbfr;

    sbfr = str;
    b = dec64_val %10; 
    dec64_val = dec64_val / 10;

    if(dec64_val)
    {
        dec64_to_str(dec64_val, sbfr);
    }
    *sbfr = '0' + b;
    sbfr++;
}


/*convert hex to bytes*/
int hex0xstr_to_char(const char *hex_str, unsigned char *byte_array, int byte_array_max)
{
    int hex_str_len = strlen(hex_str) - 2;
    int i = 2, j = 0;
    unsigned int long_ch;

    // The output array size is half the hex_str length (rounded up)
    int byte_array_size = (hex_str_len+1)/2;

    if (byte_array_size > byte_array_max)
    {
        // Too big for the output array
        return -1;
    }

    for (; i < hex_str_len+2; i+=2, j++)
    {
        if (sscanf(&(hex_str[i]), "%02X", &long_ch) != 1)
        {
            return -1;
        }
        else
        {
            byte_array[j] = (char)long_ch;
        }
    }

    return byte_array_size;
}



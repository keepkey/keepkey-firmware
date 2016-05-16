/**
 * Copyright (c) 2016 Nick Johnson
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

 #include "hex.h"

int hex_encode_address(const uint8_t *data, int datalen, char *str, int strsize) {
	if (strsize < datalen * 2)
	{
		return -1;
	}

	str[0] = '0';
	str[1] = 'x';

	for (int i = 0; i < datalen; i++)
	{
		for (int nybble = 0; nybble < 2; nybble++)
		{
			int value = (data[i] >> (nybble * 4)) & 0xF;
			if (value < 10)
			{
				str[i * 2 - nybble + 3] = '0' + value;
			} else {
				str[i * 2 - nybble + 3] = 'a' + (value - 10);
			}
		}
	}
	return 0;
}

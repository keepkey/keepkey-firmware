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

#include <stdint.h>

#include <signatures.h>
#include <ecdsa.h>

#define PUBKEYS 5
#define PUBKEY_LENGTH 65 /* NULL character included */
#define DEBUGSIG

#ifdef DEBUGSIG
static const uint8_t pubkey[PUBKEYS][PUBKEY_LENGTH] = 
{
    {
	  /*"\x04\x49\x61\x2a\xa7\x12\x4c\xb1\x50\x29\x62\x2b\x67\xf2\x7e\x7f\xa7\xbf\x41\x2f\xc6\xa7\x44\x80\xe1\x79\x20\x9a\xb2\xfc\x9b\x6b\x5b\xd3\x74\xfa\x2a\x55\x59\x86\x14\x5c\x5e\x8b\x53\xc3\x20\x94\x54\x15\x80\xea\x83\x21\x52\x1c\x63\xae\x20\x82\xe8\x9a\xb7\xec\x64"*/
	  0x04, 0x49, 0x61, 0x2a, 0xa7, 0x12, 0x4c, 0xb1, 0x50, 0x29, 0x62, 0x2b, 0x67, 0xf2, 0x7e, 0x7f, 0xa7, 0xbf, 0x41, 0x2f, 
      0xc6, 0xa7, 0x44, 0x80, 0xe1, 0x79, 0x20, 0x9a, 0xb2, 0xfc, 0x9b, 0x6b, 0x5b, 0xd3, 0x74, 0xfa, 0x2a, 0x55, 0x59, 0x86, 
      0x14, 0x5c, 0x5e, 0x8b, 0x53, 0xc3, 0x20, 0x94, 0x54, 0x15, 0x80, 0xea, 0x83, 0x21, 0x52, 0x1c, 0x63, 0xae, 0x20, 0x82, 
      0xe8, 0x9a, 0xb7, 0xec, 0x64
    }, 

    {
    /*\x04\xff\x88\x77\x68\xc9\x56\x5c\xc6\x30\xc8\xf0\x13\x96\xdd\x2b\x0b\xf5\x20\x91\x3f\x53\xf2\xf3\x1e\x4f\xe9\x21\x81\xc6\xca\x44\xca\xd3\xb6\xe6\xde\x69\x12\x96\x3c\x05\x63\x1a\xe6\xcc\xe7\xdc\x8c\xa7\x21\x11\xd3\xc8\x26\x37\x3d\x10\x4e\xc2\x91\x85\x51\x8d\x29"*/
      0x04, 0xff, 0x88, 0x77, 0x68, 0xc9, 0x56, 0x5c, 0xc6, 0x30, 0xc8, 0xf0, 0x13, 0x96, 0xdd, 0x2b, 0x0b, 0xf5, 0x20, 0x91, 
      0x3f, 0x53, 0xf2, 0xf3, 0x1e, 0x4f, 0xe9, 0x21, 0x81, 0xc6, 0xca, 0x44, 0xca, 0xd3, 0xb6, 0xe6, 0xde, 0x69, 0x12, 0x96, 
      0x3c, 0x05, 0x63, 0x1a, 0xe6, 0xcc, 0xe7, 0xdc, 0x8c, 0xa7, 0x21, 0x11, 0xd3, 0xc8, 0x26, 0x37, 0x3d, 0x10, 0x4e, 0xc2, 
      0x91, 0x85, 0x51, 0x8d, 0x29
    },
    {
	/*\x04\x31\x65\xfc\x84\x07\x40\xf8\xd8\xdb\x33\xa5\x54\x4f\x23\xcf\x63\xd1\x3a\xcb\xb9\x54\x82\xcd\x7a\x7c\xc5\x5f\x2b\xfa\x38\x3a\x9d\x5a\x7f\xf7\x2a\xad\xd9\x1b\x98\x1a\x6c\xc6\x83\xd3\x1a\x14\xd9\x1f\x35\x33\xd3\xf0\xb2\x04\x44\x66\x67\x90\x72\x99\x0a\x44\x24"*/
	  0x04, 0x31, 0x65, 0xfc, 0x84, 0x07, 0x40, 0xf8, 0xd8, 0xdb, 0x33, 0xa5, 0x54, 0x4f, 0x23, 0xcf, 0x63, 0xd1, 0x3a, 0xcb, 
      0xb9, 0x54, 0x82, 0xcd, 0x7a, 0x7c, 0xc5, 0x5f, 0x2b, 0xfa, 0x38, 0x3a, 0x9d, 0x5a, 0x7f, 0xf7, 0x2a, 0xad, 0xd9, 0x1b, 
      0x98, 0x1a, 0x6c, 0xc6, 0x83, 0xd3, 0x1a, 0x14, 0xd9, 0x1f, 0x35, 0x33, 0xd3, 0xf0, 0xb2, 0x04, 0x44, 0x66, 0x67, 0x90, 
      0x72, 0x99, 0x0a, 0x44, 0x24
    },
    {
	/*"\x04\x72\x3d\xbd\x89\x80\xc2\x24\x07\x36\x03\xc7\x0e\x99\xe1\xb3\xc9\x83\xa2\x5d\xc0\x39\x59\x42\x65\xfd\x13\x30\x2a\xf9\x87\x2a\x3a\xcd\x16\x20\xc3\x01\x00\x46\xb4\xbc\x80\x6d\x9f\x9f\x96\x00\x89\x9c\xf0\xd5\x70\xed\xc2\xec\x04\x34\x71\x54\x4f\xf6\x7c\xcb\x6d"*/
	  0x04, 0x72, 0x3d, 0xbd, 0x89, 0x80, 0xc2, 0x24, 0x07, 0x36, 0x03, 0xc7, 0x0e, 0x99, 0xe1, 0xb3, 0xc9, 0x83, 0xa2, 0x5d, 
      0xc0, 0x39, 0x59, 0x42, 0x65, 0xfd, 0x13, 0x30, 0x2a, 0xf9, 0x87, 0x2a, 0x3a, 0xcd, 0x16, 0x20, 0xc3, 0x01, 0x00, 0x46, 
      0xb4, 0xbc, 0x80, 0x6d, 0x9f, 0x9f, 0x96, 0x00, 0x89, 0x9c, 0xf0, 0xd5, 0x70, 0xed, 0xc2, 0xec, 0x04, 0x34, 0x71, 0x54, 
      0x4f, 0xf6, 0x7c, 0xcb, 0x6d
    },
    {
	/*(uint8_t *)"\x04\xc5\xb6\x2a\x94\xf2\xdb\xd7\x49\x78\xd5\x49\x90\xda\xc9\xb8\xf4\xaa\x48\x61\x96\x97\x45\xf1\x32\x8f\x19\x6c\x38\xa2\x43\x5c\xe5\x95\xaa\x14\xc2\x0c\x44\x88\x9d\x24\x80\x92\x93\x54\x04\xad\x84\xc6\xa4\xcc\x39\x7d\x06\x36\xbe\x0e\x0f\xd6\x5a\xf5\xcc\x75\x08"*/
	  0x04, 0xc5, 0xb6, 0x2a, 0x94, 0xf2, 0xdb, 0xd7, 0x49, 0x78, 0xd5, 0x49, 0x90, 0xda, 0xc9, 0xb8, 0xf4, 0xaa, 0x48, 0x61, 
      0x96, 0x97, 0x45, 0xf1, 0x32, 0x8f, 0x19, 0x6c, 0x38, 0xa2, 0x43, 0x5c, 0xe5, 0x95, 0xaa, 0x14, 0xc2, 0x0c, 0x44, 0x88, 
      0x9d, 0x24, 0x80, 0x92, 0x93, 0x54, 0x04, 0xad, 0x84, 0xc6, 0xa4, 0xcc, 0x39, 0x7d, 0x06, 0x36, 0xbe, 0x0e, 0x0f, 0xd6, 
      0x5a, 0xf5, 0xcc, 0x75, 0x08
    }
};
#else
static const uint8_t *pubkey[PUBKEYS] = {
	(uint8_t *)"\x04\xd5\x71\xb7\xf1\x48\xc5\xe4\x23\x2c\x38\x14\xf7\x77\xd8\xfa\xea\xf1\xa8\x42\x16\xc7\x8d\x56\x9b\x71\x04\x1f\xfc\x76\x8a\x5b\x2d\x81\x0f\xc3\xbb\x13\x4d\xd0\x26\xb5\x7e\x65\x00\x52\x75\xae\xde\xf4\x3e\x15\x5f\x48\xfc\x11\xa3\x2e\xc7\x90\xa9\x33\x12\xbd\x58",
	(uint8_t *)"\x04\x63\x27\x9c\x0c\x08\x66\xe5\x0c\x05\xc7\x99\xd3\x2b\xd6\xba\xb0\x18\x8b\x6d\xe0\x65\x36\xd1\x10\x9d\x2e\xd9\xce\x76\xcb\x33\x5c\x49\x0e\x55\xae\xe1\x0c\xc9\x01\x21\x51\x32\xe8\x53\x09\x7d\x54\x32\xed\xa0\x6b\x79\x20\x73\xbd\x77\x40\xc9\x4c\xe4\x51\x6c\xb1",
	(uint8_t *)"\x04\x43\xae\xdb\xb6\xf7\xe7\x1c\x56\x3f\x8e\xd2\xef\x64\xec\x99\x81\x48\x25\x19\xe7\xef\x4f\x4a\xa9\x8b\x27\x85\x4e\x8c\x49\x12\x6d\x49\x56\xd3\x00\xab\x45\xfd\xc3\x4c\xd2\x6b\xc8\x71\x0d\xe0\xa3\x1d\xbd\xf6\xde\x74\x35\xfd\x0b\x49\x2b\xe7\x0a\xc7\x5f\xde\x58",
	(uint8_t *)"\x04\x87\x7c\x39\xfd\x7c\x62\x23\x7e\x03\x82\x35\xe9\xc0\x75\xda\xb2\x61\x63\x0f\x78\xee\xb8\xed\xb9\x24\x87\x15\x9f\xff\xed\xfd\xf6\x04\x6c\x6f\x8b\x88\x1f\xa4\x07\xc4\xa4\xce\x6c\x28\xde\x0b\x19\xc1\xf4\xe2\x9f\x1f\xcb\xc5\xa5\x8f\xfd\x14\x32\xa3\xe0\x93\x8a",
	(uint8_t *)"\x04\x73\x84\xc5\x1a\xe8\x1a\xdd\x0a\x52\x3a\xdb\xb1\x86\xc9\x1b\x90\x6f\xfb\x64\xc2\xc7\x65\x80\x2b\xf2\x6d\xbd\x13\xbd\xf1\x2c\x31\x9e\x80\xc2\x21\x3a\x13\x6c\x8e\xe0\x3d\x78\x74\xfd\x22\xb7\x0d\x68\xe7\xde\xe4\x69\xde\xcf\xbb\xb5\x10\xee\x9a\x46\x0c\xda\x45",
};
#endif

#define SIGNATURES 3


int signatures_ok(void)
{
	uint32_t codelen = *((uint32_t *)FLASH_META_CODELEN);
	uint8_t sigindex1, sigindex2, sigindex3;

	sigindex1 = *((uint8_t *)FLASH_META_SIGINDEX1);
	sigindex2 = *((uint8_t *)FLASH_META_SIGINDEX2);
	sigindex3 = *((uint8_t *)FLASH_META_SIGINDEX3);

	if (sigindex1 < 1 || sigindex1 > PUBKEYS) return 0; // invalid index
	if (sigindex2 < 1 || sigindex2 > PUBKEYS) return 0; // invalid index
	if (sigindex3 < 1 || sigindex3 > PUBKEYS) return 0; // invalid index

	if (sigindex1 == sigindex2) return 0; // duplicate use
	if (sigindex1 == sigindex3) return 0; // duplicate use
	if (sigindex2 == sigindex3) return 0; // duplicate use

	if (ecdsa_verify(&pubkey[sigindex1 - 1][0], (uint8_t *)FLASH_META_SIG1, (uint8_t *)FLASH_APP_START, codelen) != 0) { // failure
        dbg_print("sigindex1-1 failed\n\r");
		return 0;
	}
    else
    {
        dbg_print("sigindex1-1 passed\n\r");
    }
	if (ecdsa_verify(&pubkey[sigindex2 - 1][0], (uint8_t *)FLASH_META_SIG2, (uint8_t *)FLASH_APP_START, codelen) != 0) { // failure
		return 0;
	}
	if (ecdsa_verify(&pubkey[sigindex3 - 1][0], (uint8_t *)FLASH_META_SIG3, (uint8_t *)FLASH_APP_START, codelen) != 0) { // failture
		return 0;
	}
	return(1);
}

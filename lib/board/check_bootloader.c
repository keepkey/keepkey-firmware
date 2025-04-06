/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2018 keepkeyjon <jon@keepkey.com>
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

#include "keepkey/board/check_bootloader.h"

#ifndef EMULATOR
#include <libopencm3/stm32/flash.h>
#endif

#include "hwcrypto/crypto/sha2.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/memory.h"

#include <inttypes.h>
#include <string.h>

char bl_hash_v1_0_0_hotpatched[32] =
    "\xf1\x3c\xe2\x28\xc0\xbb\x2b\xdb\xc5\x6b\xdc\xb5\xf4\x56\x93\x67\xf8\xe3"
    "\x01\x10\x74\xcc\xc6\x33\x31\x34\x8d\xeb\x49\x8f\x2d\x8f";
char bl_hash_v1_0_1_hotpatched[32] =
    "\xec\x61\x88\x36\xf8\x64\x23\xdb\xd3\x11\x4c\x37\xd6\xe3\xe4\xff\xdf\xb8"
    "\x7d\x9e\x4c\x61\x99\xcf\x3e\x16\x3a\x67\xb2\x74\x98\xa2";
char bl_hash_v1_0_2_hotpatched[32] =
    "\xbc\xaf\xb3\x8c\xd0\xfb\xd6\xe2\xbd\xbe\xa8\x9f\xb9\x02\x35\x55\x9f\xdd"
    "\xa3\x60\x76\x5b\x74\xe4\xa8\x75\x8b\x4e\xff\x2d\x49\x21";
char bl_hash_v1_0_3_hotpatched[32] =
    "\x83\xd1\x4c\xb6\xc7\xc4\x8a\xf2\xa8\x3b\xc3\x26\x35\x3e\xe6\xb9\xab\xdd"
    "\x74\xcf\xe4\x7b\xa5\x67\xde\x1c\xb5\x64\xda\x65\xe8\xe9";
char bl_hash_v1_0_3_sig_hotpatched[32] =
    "\x91\x7d\x19\x52\x26\x0c\x9b\x89\xf3\xa9\x6b\xea\x07\xee\xa4\x07\x4a\xfd"
    "\xcc\x0e\x8c\xdd\x5d\x06\x4e\x36\x86\x8b\xdd\x68\xba\x7d";
char bl_hash_v1_0_3_elf_hotpatched[32] =
    "\xdb\x4b\xc3\x89\x33\x5e\x87\x6e\x94\x2a\xe3\xb1\x25\x58\xce\xcd\x20\x2b"
    "\x74\x59\x03\xe7\x9b\x34\xdd\x2c\x32\x53\x27\x08\x86\x0e";
char bl_hash_v1_0_4_hotpatched[32] =
    "\xfc\x4e\x5c\x4d\xc2\xe5\x12\x7b\x68\x14\xa3\xf6\x94\x24\xc9\x36\xf1\xdc"
    "\x24\x1d\x1d\xaf\x2c\x5a\x2d\x8f\x07\x28\xeb\x69\xd2\x0d";

char bl_hash_v1_0_0_unpatched[32] =
    "\x63\x97\xc4\x46\xf6\xb9\x00\x2a\x8b\x15\x0b\xf4\xb9\xb4\xe0\xbb\x66\x80"
    "\x0e\xd0\x99\xb8\x81\xca\x49\x70\x01\x39\xb0\x55\x9f\x10";
char bl_hash_v1_0_1_unpatched[32] =
    "\xd5\x44\xb5\xe0\x6b\x0c\x35\x5d\x68\xb8\x68\xac\x75\x80\xe9\xba\xb2\xd2"
    "\x24\xa1\xe2\x44\x08\x81\xcc\x1b\xca\x2b\x81\x67\x52\xd5";
char bl_hash_v1_0_2_unpatched[32] =
    "\xcd\x70\x2b\x91\x02\x8a\x2c\xfa\x55\xaf\x43\xd3\x40\x7b\xa0\xf6\xf7\x52"
    "\xa4\xa2\xbe\x05\x83\xa1\x72\x98\x3b\x30\x3a\xb1\x03\x2e";
char bl_hash_v1_0_3_unpatched[32] =
    "\x2e\x38\x95\x01\x43\xcf\x35\x03\x45\xa6\xdd\xad\xa4\xc0\xc4\xf2\x1e\xb2"
    "\xed\x33\x73\x09\xf3\x9c\x5d\xbc\x70\xb6\xc0\x91\xae\x00";
char bl_hash_v1_0_3_sig_unpatched[32] =
    "\xcb\x22\x25\x48\xa3\x9f\xf6\xcb\xe2\xae\x2f\x02\xc8\xd4\x31\xc9\xae\x0d"
    "\xf8\x50\xf8\x14\x44\x49\x11\xf5\x21\xb9\x5a\xb0\x2f\x4c";
char bl_hash_v1_0_3_elf_unpatched[32] =
    "\x64\x65\xbc\x50\x55\x86\x70\x0a\x81\x11\xc4\xbf\x7d\xb6\xf4\x0a\xf7\x3e"
    "\x72\x0f\x9e\x48\x8d\x20\xdb\x56\x13\x5e\x5a\x69\x0c\x4f";
char bl_hash_v1_0_4_unpatched[32] =
    "\x77\x0b\x30\xaa\xa0\xbe\x88\x4e\xe8\x62\x18\x59\xf5\xd0\x55\x43\x7f\x89"
    "\x4a\x5c\x9c\x7c\xa2\x26\x35\xe7\x02\x4e\x05\x98\x57\xb7";

char bl_hash_v1_1_0[32] =
    "\xe4\x5f\x58\x7f\xb0\x75\x33\xd8\x32\x54\x84\x02\xd0\xe7\x1d\x8e\x82\x34"
    "\x88\x1d\xa5\x4d\x86\xc4\xb6\x99\xc2\x8a\x64\x82\xb0\xee";
char bl_hash_v2_0_0[32] =
    "\x9b\xf1\x58\x0d\x1b\x21\x25\x0f\x92\x2b\x68\x79\x4c\xda\xdd\x6c\x8e\x16"
    "\x6a\xe5\xb1\x5c\xe1\x60\xa4\x2f\x8c\x44\xa2\xf0\x59\x36";
char bl_hash_v2_1_0[32] =
    "\xe1\xad\x26\x67\xd1\x92\x4e\x4d\xdb\xeb\x62\x3b\xd6\x93\x9e\x94\x11\x4d"
    "\x84\x71\xb8\x4f\x8f\xb0\x56\xe0\xc9\xab\xf0\xc4\xe4\xf4";
char bl_hash_v2_1_1[32] =
    "\xa3\xf8\xc7\x45\xff\x33\xcd\x92\xa7\xe9\x5d\x37\xc7\x6c\x65\x52\x3d\x25"
    "\x8a\x70\x35\x2e\xa4\x4a\x23\x20\x38\xec\x4e\xc3\x8d\xea";
char bl_hash_v2_1_2[32] =
    "\x3b\x97\x59\x6e\xd6\x12\xaa\x29\xa7\x4a\x7f\x51\xf3\x3e\xa8\x5f\xd6\xe0"
    "\xcf\xe7\x34\x0d\xfb\xb9\x6f\x0c\x17\x07\x7b\x36\x34\x98";
char bl_hash_v2_1_3[32] =
    "\xe6\x68\x5a\xb1\x48\x44\xd0\xa3\x81\xd6\x58\xd7\x7e\x13\xd6\x14\x5f\xe7"
    "\xae\x80\x46\x9e\x5a\x53\x60\x21\x0a\xe9\xc3\x44\x7a\x77";
char bl_hash_v2_1_4[32] =
    "\xfe\x98\x45\x4e\x7e\xbd\x4a\xef\x4a\x6d\xb5\xbd\x4c\x60\xf5\x2c\xf3\xf5"
    "\x8b\x97\x42\x83\xa7\xc1\xe1\xfc\xc5\xfe\xa0\x2c\xf3\xeb";

BootloaderKind get_bootloaderKind(void) {
  static uint8_t bl_hash[SHA256_DIGEST_LENGTH];
  if (32 != memory_bootloader_hash(bl_hash, /*cached=*/false))
    return BLK_UNKNOWN;

  // Hotpatch unnecessary
  // --------------------
  if (0 == memcmp(bl_hash, bl_hash_v1_1_0, 32)) return BLK_v1_1_0;

  if (0 == memcmp(bl_hash, bl_hash_v2_0_0, 32)) return BLK_v2_0_0;

  if (0 == memcmp(bl_hash, bl_hash_v2_1_0, 32)) return BLK_v2_1_0;

  if (0 == memcmp(bl_hash, bl_hash_v2_1_1, 32)) return BLK_v2_1_1;

  if (0 == memcmp(bl_hash, bl_hash_v2_1_2, 32)) return BLK_v2_1_2;

  if (0 == memcmp(bl_hash, bl_hash_v2_1_3, 32)) return BLK_v2_1_3;

  if (0 == memcmp(bl_hash, bl_hash_v2_1_4, 32)) return BLK_v2_1_4;

  // Hotpatched bootloaders
  // ----------------------
  if (0 == memcmp(bl_hash, bl_hash_v1_0_0_hotpatched, 32)) return BLK_v1_0_0;

  if (0 == memcmp(bl_hash, bl_hash_v1_0_1_hotpatched, 32)) return BLK_v1_0_1;

  if (0 == memcmp(bl_hash, bl_hash_v1_0_2_hotpatched, 32)) return BLK_v1_0_2;

  if (0 == memcmp(bl_hash, bl_hash_v1_0_3_hotpatched, 32)) return BLK_v1_0_3;

  if (0 == memcmp(bl_hash, bl_hash_v1_0_3_sig_hotpatched, 32))
    return BLK_v1_0_3_sig;

  if (0 == memcmp(bl_hash, bl_hash_v1_0_3_elf_hotpatched, 32))
    return BLK_v1_0_3_elf;

  if (0 == memcmp(bl_hash, bl_hash_v1_0_4_hotpatched, 32)) return BLK_v1_0_4;

  // Unpatched bootloaders
  // ---------------------
  if (0 == memcmp(bl_hash, bl_hash_v1_0_0_unpatched, 32)) return BLK_v1_0_0;

  if (0 == memcmp(bl_hash, bl_hash_v1_0_1_unpatched, 32)) return BLK_v1_0_1;

  if (0 == memcmp(bl_hash, bl_hash_v1_0_2_unpatched, 32)) return BLK_v1_0_2;

  if (0 == memcmp(bl_hash, bl_hash_v1_0_3_unpatched, 32)) return BLK_v1_0_3;

  if (0 == memcmp(bl_hash, bl_hash_v1_0_3_sig_unpatched, 32))
    return BLK_v1_0_3_sig;

  if (0 == memcmp(bl_hash, bl_hash_v1_0_3_elf_unpatched, 32))
    return BLK_v1_0_3_elf;

  if (0 == memcmp(bl_hash, bl_hash_v1_0_4_unpatched, 32)) return BLK_v1_0_4;

  return BLK_UNKNOWN;
}

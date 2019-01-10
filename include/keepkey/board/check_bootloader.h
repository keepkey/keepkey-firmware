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

#ifndef KEEPKEY_BOARD_CHECKBOOTLOADER_H
#define KEEPKEY_BOARD_CHECKBOOTLOADER_H

extern char bl_hash_v1_0_0_hotpatched[32];
extern char bl_hash_v1_0_1_hotpatched[32];
extern char bl_hash_v1_0_2_hotpatched[32];
extern char bl_hash_v1_0_3_hotpatched[32];
extern char bl_hash_v1_0_3_sig_hotpatched[32];
extern char bl_hash_v1_0_3_elf_hotpatched[32];
extern char bl_hash_v1_0_4_hotpatched[32];

extern char bl_hash_v1_0_0_unpatched[32];
extern char bl_hash_v1_0_1_unpatched[32];
extern char bl_hash_v1_0_2_unpatched[32];
extern char bl_hash_v1_0_3_unpatched[32];
extern char bl_hash_v1_0_3_sig_unpatched[32];
extern char bl_hash_v1_0_3_elf_unpatched[32];
extern char bl_hash_v1_0_4_unpatched[32];

extern char bl_hash_v1_1_0[32];
extern char bl_hash_v2_0_0[32];


typedef enum _BootloaderKind {
    BLK_UNKNOWN,
    BLK_v1_0_0,
    BLK_v1_0_1,
    BLK_v1_0_2,
    BLK_v1_0_3,
    BLK_v1_0_3_sig,
    BLK_v1_0_3_elf,
    BLK_v1_0_4,
    BLK_v1_1_0,
    BLK_v2_0_0
} BootloaderKind;

BootloaderKind get_bootloaderKind(void);

#endif


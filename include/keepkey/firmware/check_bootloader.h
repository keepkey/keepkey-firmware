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

#ifndef CHECK_BOOTLOADER_H
#define CHECK_BOOTLOADER_H

void check_bootloader(void);

typedef enum _BootloaderKind {
    BLK_UNKONWN,
    BLK_v1_0_0,
    BLK_v1_0_1,
    BLK_v1_0_2,
    BLK_v1_0_3,
    BLK_v1_0_3_sig,
    BLK_v1_0_3_elf,
    BLK_v1_0_4,
} BootloaderKind;

BootloaderKind get_bootloaderKind(void);

#endif

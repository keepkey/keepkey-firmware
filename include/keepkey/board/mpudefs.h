/*
 * Copyright (C) 2018 KeepKey
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

#ifndef MPUDEFS_H
#define MPUDEFS_H


// MPU
#define MPU_RASR_SIZE_512B  (0x08UL << MPU_RASR_SIZE_LSB)
#define MPU_RASR_SIZE_1KB   (0x09UL << MPU_RASR_SIZE_LSB)
#define MPU_RASR_SIZE_2KB   (0x0AUL << MPU_RASR_SIZE_LSB)
#define MPU_RASR_SIZE_4KB   (0x0BUL << MPU_RASR_SIZE_LSB)
#define MPU_RASR_SIZE_8KB   (0x0CUL << MPU_RASR_SIZE_LSB)
#define MPU_RASR_SIZE_16KB  (0x0DUL << MPU_RASR_SIZE_LSB)
#define MPU_RASR_SIZE_32KB  (0x0EUL << MPU_RASR_SIZE_LSB)
#define MPU_RASR_SIZE_64KB  (0x0FUL << MPU_RASR_SIZE_LSB)
#define MPU_RASR_SIZE_128KB (0x10UL << MPU_RASR_SIZE_LSB)
#define MPU_RASR_SIZE_256KB (0x11UL << MPU_RASR_SIZE_LSB)
#define MPU_RASR_SIZE_512KB (0x12UL << MPU_RASR_SIZE_LSB)
#define MPU_RASR_SIZE_1MB   (0x13UL << MPU_RASR_SIZE_LSB)
#define MPU_RASR_SIZE_512MB (0x1CUL << MPU_RASR_SIZE_LSB)

// http://infocenter.arm.com/help/topic/com.arm.doc.dui0552a/BABDJJGF.html
#define MPU_RASR_ATTR_FLASH  (MPU_RASR_ATTR_C)
#define MPU_RASR_ATTR_SRAM   (MPU_RASR_ATTR_C | MPU_RASR_ATTR_S)
#define MPU_RASR_ATTR_PERIPH (MPU_RASR_ATTR_B | MPU_RASR_ATTR_S)

// subregion disable bits
#define MPU_RASR_DIS_SUB_8  (0b10000000UL << 8)

#define FLASH_BASE      (0x08000000U)
#define SRAM_BASE       (0x20000000U)
#define BLPROTECT_BASE  (0x2001F800U)


#endif
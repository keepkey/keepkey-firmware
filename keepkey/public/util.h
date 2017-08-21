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

#ifndef UTIL_H
#define UTIL_H

/* === Includes ============================================================ */

#include <stdint.h>
#include <stdio.h>
#include <libopencm3/cm3/vector.h>
#include <libopencm3/cm3/scb.h>

/* === Functions =========================================================== */

// converts uint32 to hexa (8 digits)
void uint32hex(uint32_t num, char *str);

// converts data to hexa
void data2hex(const void *data, uint32_t len, char *str);

// read protobuf integer and advance pointer
uint32_t readprotobufint(uint8_t **ptr);
void rev_byte_order(uint8_t *bfr, size_t len);
void dec64_to_str(uint64_t dec64_val, char *str);

// defined in memory.ld
extern uint8_t _ram_start[], _ram_end[];

// defined in startup.s
extern void memset_reg(void *start, void *stop, uint32_t val);

static inline void __attribute__((noreturn)) load_vector_table(const vector_table_t *vector_table)
{
    SCB_VTOR = (uint32_t)vector_table; // Relocate vector table
    __asm__ volatile("msr msp, %0" :: "r" (vector_table->initial_sp_value)); // Set stack pointer
    vector_table->reset(); // Jump to address
    for (;;); // Prevent compiler from generating stack protector code (which causes CPU fault because the stack is moved)
}
#endif

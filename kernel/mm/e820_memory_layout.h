/*
 * QEMU BIOS e820 routines
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdbool.h>
#ifndef HW_I386_E820_MEMORY_LAYOUT_H
#define HW_I386_E820_MEMORY_LAYOUT_H

/* e820 types */
#define E820_RAM        1
#define E820_RESERVED   2
#define E820_ACPI       3
#define E820_NVS        4
#define E820_UNUSABLE   5

struct e820_entry {
    uint64_t address;
    uint64_t length;
    uint32_t type;
}  __attribute((packed,__aligned__(4)));



#endif

#pragma once

#include <stdint.h>

typedef struct
{
    uint16_t segment_limit_low;
    uint16_t base_address_low;
    uint32_t base_address_middle : 8;
    uint32_t type : 4;
    uint32_t descriptor_type : 1;
    uint32_t descriptor_privilege_level : 2;
    uint32_t present : 1;
    uint32_t segment_limit_high : 4;
    uint32_t available_bit : 1;
    uint32_t long_mode : 1;
    uint32_t default_big : 1;
    uint32_t granularity : 1;
    uint32_t base_address_high : 8;
} gdt_desc_t;

typedef struct
{
    uint16_t segment_limit_low;
    uint16_t base_address_low;
    uint32_t base_address_middle : 8;
    uint32_t type : 4;
    uint32_t descriptor_type : 1;
    uint32_t descriptor_privilege_level : 2;
    uint32_t present : 1;
    uint32_t segment_limit_high : 4;
    uint32_t available_bit : 1;
    uint32_t long_mode : 1;
    uint32_t default_big : 1;
    uint32_t granularity : 1;
    uint32_t base_address_high : 8;
    uint32_t base_address_upper;
    uint32_t must_be_zero;
} gdt_desc64_t;

typedef struct
{
    uint32_t reserved_0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved_1;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved_2;
    uint16_t reserved_3;
    uint16_t io_map_base;
} tss64_t;

typedef struct
{
    gdt_desc_t null;
    gdt_desc_t code;
    gdt_desc64_t task;
} gdt_data_t;

void build_gdt(gdt_data_t *gdt, tss64_t *tss);
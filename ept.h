#pragma once

#include <stdint.h>
#include "basic_lib.h"

typedef union
{
    struct
    {
        uint64_t read : 1;
        uint64_t write : 1;
        uint64_t execute : 1;
        uint64_t reserved0 : 5;
        uint64_t accessed : 1;
        uint64_t ignored0 : 1;
        uint64_t umx : 1;
        uint64_t ignored1 : 1;
        uint64_t pdpt_offset : 40;
        uint64_t reserved1 : 12;
    };
    uint64_t all;
} ept_pml4e_t;

typedef union
{
    struct
    {
        uint64_t read : 1;
        uint64_t write : 1;
        uint64_t execute : 1;
        uint64_t reserved0 : 5;
        uint64_t accessed : 1;
        uint64_t ignored0 : 1;
        uint64_t umx : 1;
        uint64_t ignored1 : 1;
        uint64_t pd_offset : 40;
        uint64_t ignored2 : 12;
    };
    uint64_t all;
} ept_pdpte_t;

typedef union

{
    struct
    {
        uint64_t read : 1;
        uint64_t write : 1;
        uint64_t execute : 1;
        uint64_t memory_type : 3;
        uint64_t ignore_pat : 1;
        uint64_t large_pde : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t umx : 1;
        uint64_t ignored0 : 1;
        uint64_t reserved : 9;
        uint64_t page_offset : 31;
        uint64_t ignored1 : 8;
        uint64_t s_shadow_stack : 1;
        uint64_t ignored2 : 2;
        uint64_t suppress_ve : 1;
    };
    uint64_t all;
} ept_large_pde_t;

typedef union
{
    ept_large_pde_t large;
    struct
    {
        uint64_t read : 1;
        uint64_t write : 1;
        uint64_t execute : 1;
        uint64_t reserved0 : 5;
        uint64_t accessed : 1;
        uint64_t ignored0 : 1;
        uint64_t umx : 1;
        uint64_t ignored1 : 1;
        uint64_t pt_offset : 40;
        uint64_t ignored2 : 12;
    };
    uint64_t all;
} ept_pde_t;

typedef union
{
    struct
    {
        uint64_t read : 1;
        uint64_t write : 1;
        uint64_t execute : 1;
        uint64_t memory_type : 3;
        uint64_t ignore_pat : 1;
        uint64_t ignored0 : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t umx : 1;
        uint64_t ignored1 : 1;
        uint64_t page_offset : 40;
        uint64_t ignored2 : 8;
        uint64_t s_shadow_stack : 1;
        uint64_t subpage_write : 1;
        uint64_t ignored3 : 1;
        uint64_t suppress_ve : 1;
    };
    uint64_t all;
} ept_pte_t;

typedef union
{
    struct
    {

        uint64_t memory_type : 3;  // bits	0-2
        uint64_t walk_length : 3;  // bits	3-5
        uint64_t dirty_flag : 1;   // bit	6
        uint64_t enable_sss : 1;   // bit	7
        uint64_t reserved : 4;     // bits	8-11
        uint64_t pml4_offset : 52; // bits	12-63
    };
    uint64_t all;
} eptp_t;

#define EPT_PT_NUM 512

typedef struct
{
    ept_pml4e_t pml4[512];
    ept_pdpte_t pdpt[512];   // 只映射低512GB内存
    ept_pde_t pds[512][512]; // 初始化时使用2MB大页映射
    ept_pte_t pts[EPT_PT_NUM][512];
} ept_data_t;

typedef struct
{
    ept_data_t *ept;
    uint8_t pt_bitmap[EPT_PT_NUM / 8 + 1]; // 使用位图指示被使用的PT页表
    eptp_t eptp;
} ept_mgr_t;

void init_ept(ept_mgr_t *mgr);
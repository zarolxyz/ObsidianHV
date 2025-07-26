#pragma once

#include <stdint.h>
#include "basic_lib.h"

#pragma pack(push, 1)

typedef union
{
    struct
    {
        uint64_t read_access : 1;
        uint64_t write_access : 1;
        uint64_t execute_access : 1;
        uint64_t reserved_1 : 5;
        uint64_t accessed : 1;
        uint64_t reserved_2 : 1;
        uint64_t user_mode_execute : 1;
        uint64_t reserved_3 : 1;
        uint64_t page_frame_number : 36;
    };

    uint64_t all;
} ept_pml4e_t;

typedef union
{
    struct
    {
        uint64_t read_access : 1;
        uint64_t write_access : 1;
        uint64_t execute_access : 1;
        uint64_t reserved_1 : 5;
        uint64_t accessed : 1;
        uint64_t reserved_2 : 1;
        uint64_t user_mode_execute : 1;
        uint64_t reserved_3 : 1;
        uint64_t page_frame_number : 36;
    };

    uint64_t all;
} ept_pdpte_t;

typedef union

{
    struct
    {
        uint64_t read_access : 1;
        uint64_t write_access : 1;
        uint64_t execute_access : 1;
        uint64_t memory_type : 3;
        uint64_t ignore_pat : 1;
        uint64_t large_page : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t user_mode_execute : 1;
        uint64_t reserved_1 : 10;
        uint64_t page_frame_number : 27;
        uint64_t reserved_2 : 9;
        uint64_t verify_guest_paging : 1;
        uint64_t paging_write_access : 1;
        uint64_t reserved_3 : 1;
        uint64_t supervisor_shadow_stack : 1;
        uint64_t reserved_4 : 2;
        uint64_t suppress_ve : 1;
    };
    uint64_t all;
} ept_large_pde_t;

typedef union
{
    ept_large_pde_t large;
    struct
    {
        uint64_t read_access : 1;
        uint64_t write_access : 1;
        uint64_t execute_access : 1;
        uint64_t reserved_1 : 5;
        uint64_t accessed : 1;
        uint64_t reserved_2 : 1;
        uint64_t user_mode_execute : 1;
        uint64_t reserved_3 : 1;
        uint64_t page_frame_number : 36;
    };
    uint64_t all;
} ept_pde_t;

typedef union
{
    struct
    {
        uint64_t read_access : 1;
        uint64_t write_access : 1;
        uint64_t execute_access : 1;
        uint64_t memory_type : 3;
        uint64_t ignore_pat : 1;
        uint64_t reserved_1 : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t user_mode_execute : 1;
        uint64_t reserved_2 : 1;
        uint64_t page_frame_number : 36;
        uint64_t reserved_3 : 9;
        uint64_t verify_guest_paging : 1;
        uint64_t paging_write_access : 1;
        uint64_t reserved_4 : 1;
        uint64_t supervisor_shadow_stack : 1;
        uint64_t sub_page_write_permissions : 1;
        uint64_t reserved_5 : 1;
        uint64_t suppress_ve : 1;
    };
    uint64_t all;
} ept_pte_t;

#define EPT_PAGE_WALK_LENGTH_4 0x00000003

typedef union
{
    struct
    {

        uint64_t memory_type : 3;
        uint64_t page_walk_length : 3;
        uint64_t enable_access_and_dirty_flags : 1;
        uint64_t enable_supervisor_shadow_stack_pages : 1;
        uint64_t reserved_1 : 4;
        uint64_t page_frame_number : 36;
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

#pragma pack(pop)

typedef struct
{
    ept_data_t *ept;
    uint8_t pt_bitmap[EPT_PT_NUM / 8 + 1]; // 使用位图指示被使用的PT页表
    eptp_t eptp;
} ept_mgr_t;

void init_ept(ept_mgr_t *mgr);
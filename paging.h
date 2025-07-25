#pragma once

#include <stdint.h>

typedef union
{
    struct
    {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved_1 : 1;
        uint64_t must_be_zero : 1;
        uint64_t ignored_1 : 3;
        uint64_t restart : 1;
        uint64_t page_frame_number : 36;
        uint64_t reserved_2 : 4;
        uint64_t ignored_2 : 11;
        uint64_t execute_disable : 1;
    };

    uint64_t all;
} pml4e_t;

typedef union
{
    struct
    {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t large_page : 1;
        uint64_t global : 1;
        uint64_t ignored_1 : 2;
        uint64_t restart : 1;
        uint64_t pat : 1;
        uint64_t reserved_1 : 17;
        uint64_t page_frame_number : 18;
        uint64_t reserved_2 : 4;
        uint64_t ignored_2 : 7;
        uint64_t protection_key : 4;
        uint64_t execute_disable : 1;
    };
    uint64_t all;
} large_pdpte_t;

typedef union
{
    struct
    {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved_1 : 1;
        uint64_t large_page : 1;
        uint64_t ignored_1 : 3;
        uint64_t restart : 1;
        uint64_t page_frame_number : 36;
        uint64_t reserved_2 : 4;
        uint64_t ignored_2 : 11;
        uint64_t execute_disable : 1;
    };
    large_pdpte_t large;
    uint64_t all;
} pdpte_t;

typedef struct
{
    pml4e_t pml4[512];
    pdpte_t pdpt[512];
} pt_data_t;

int check_pdpe1gb();
void build_identity_pt(pt_data_t *pt);
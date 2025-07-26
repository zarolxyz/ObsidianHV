#include "ept.h"
#include "basic_lib.h"
#include "intrin.h"
#include "basic_lib.h"

/// See: IA32_MTRRCAP Register
typedef union
{
    uint64_t all;
    struct
    {
        uint64_t variable_range_count : 8;      //!< [0:7]
        uint64_t fixed_range_supported : 1;     //!< [8]
        uint64_t reserved : 1;                  //!< [9]
        uint64_t write_combining_supported : 1; //!< [10]
        uint64_t smrr_supported : 1;            //!< [11]
    } fields;
} msr_mtrr_capabilities_t;

typedef union
{
    uint64_t all;
    struct
    {
        uint64_t default_memory_type : 8; //!< [0:7]
        uint64_t reserved : 2;            //!< [8:9]
        uint64_t fixed_mtrrs_enabled : 1; //!< [10]
        uint64_t mtrrs_enabled : 1;       //!< [11]
    } fields;
} msr_mtrr_def_type_t;

typedef union
{
    uint64_t all;
    struct
    {
        uint8_t types[8]; //!< [0:8];
    } fields;
} msr_mtrr_fixed_range_t;

typedef union
{
    uint64_t all;
    struct
    {
        uint64_t type : 8;       //!< [0:7]
        uint64_t reserved : 4;   //!< [8:11]
        uint64_t phys_base : 36; //!< [12:MAXPHYADDR]
    } fields;
} msr_mtrr_physbase_t;

typedef union
{
    uint64_t all;
    struct
    {
        uint64_t reserved : 11;  //!< [0:10]
        uint64_t valid : 1;      //!< [11]
        uint64_t phys_mask : 36; //!< [12:MAXPHYADDR]
    } fields;
} msr_mtrr_physmask_t;

#define MEMORY_TYPE_UNCACHEABLE 0x00000000
#define MEMORY_TYPE_WRITE_COMBINING 0x00000001
#define MEMORY_TYPE_WRITE_THROUGH 0x00000004
#define MEMORY_TYPE_WRITE_PROTECTED 0x00000005
#define MEMORY_TYPE_WRITE_BACK 0x00000006
#define MEMORY_TYPE_UNCACHEABLE_MINUS 0x00000007
#define MEMORY_TYPE_INVALID 0x000000FF

static ept_pde_t *get_pde(ept_data_t *ept, uint64_t addr)
{
    return &ept->pds[(addr >> 30) & 0x1ff][(addr >> 21) & 0x1ff];
}

static ept_pte_t *get_pt_from_pde(ept_pde_t *pde)
{
    return (ept_pte_t *)(((uint64_t)pde->page_frame_number << PAGE_SHIFT));
}

ept_pte_t *ept_alloc_pt(ept_mgr_t *mgr)
{
    uintptr_t index = bitmap_find_first_zero(mgr->pt_bitmap, EPT_PT_NUM);
    if (index == UINTPTR_MAX)
    {
        PRINTF("Failed to allocate PT\n");
        return NULL;
    }
    bitmap_set_bit(mgr->pt_bitmap, index);
    return mgr->ept->pts[index];
}

ept_pte_t *ept_split_pde(ept_mgr_t *mgr, ept_pde_t *pde)
{
    ept_pte_t *pt = ept_alloc_pt(mgr);
    if (pt == NULL || !pde->large.large_page)
    {
        PRINTF("Failed to split PDE\n");
        return NULL;
    }
    for (int i = 0; i < 512; i++)
    {
        pt[i] = (ept_pte_t){.page_frame_number = (pde->large.page_frame_number << 9) + i, .read_access = 1, .write_access = 1, .execute_access = 1, .memory_type = pde->large.memory_type};
    }
    *pde = (ept_pde_t){.page_frame_number = (uint64_t)pt >> PAGE_SHIFT, .read_access = 1, .write_access = 1, .execute_access = 1};
    return pt;
}

// 选择优先级高的内存类型
int select_memory_type(int type1, int type2)
{
    if (type1 == MEMORY_TYPE_UNCACHEABLE || type2 == MEMORY_TYPE_UNCACHEABLE)
    {
        return MEMORY_TYPE_UNCACHEABLE;
    }
    if (type1 == MEMORY_TYPE_UNCACHEABLE_MINUS || type2 == MEMORY_TYPE_UNCACHEABLE_MINUS)
    {
        return MEMORY_TYPE_UNCACHEABLE_MINUS;
    }
    if (type1 == MEMORY_TYPE_WRITE_COMBINING || type2 == MEMORY_TYPE_WRITE_COMBINING)
    {
        return MEMORY_TYPE_WRITE_COMBINING;
    }
    if (type1 == MEMORY_TYPE_WRITE_THROUGH || type2 == MEMORY_TYPE_WRITE_THROUGH)
    {
        return MEMORY_TYPE_WRITE_THROUGH;
    }
    if (type1 == MEMORY_TYPE_WRITE_PROTECTED || type2 == MEMORY_TYPE_WRITE_PROTECTED)
    {
        return MEMORY_TYPE_WRITE_PROTECTED;
    }
    return MEMORY_TYPE_WRITE_BACK;
}

int get_var_mtrr_type_by_range(uint64_t start, uint64_t size)
{
    return MEMORY_TYPE_WRITE_BACK;
    int current_type = MEMORY_TYPE_WRITE_BACK; // 默认为 WB
    msr_mtrr_capabilities_t mtrr_capabilities = {.all = read_msr(MSR_IA32_MTRR_CAP)};
    for (int i = 0; i < mtrr_capabilities.fields.variable_range_count; i++)
    {
        msr_mtrr_physbase_t mtrr_physbase = {.all = read_msr(MSR_IA32_MTRR_PHYS_BASE + i * 2)};
        msr_mtrr_physmask_t mtrr_physmask = {.all = read_msr(MSR_IA32_MTRR_PHYS_MASK + i * 2)};

        // 无效的 MTRR
        if (!mtrr_physmask.fields.valid || mtrr_physbase.fields.type == MEMORY_TYPE_INVALID || bit_scan(mtrr_physmask.fields.phys_mask) < 0)
        {
            continue;
        }

        uint64_t mtrr_start = mtrr_physbase.fields.phys_base << PAGE_SHIFT;
        uint64_t mtrr_end = mtrr_start + (bit_scan(mtrr_physmask.fields.phys_mask) << PAGE_SHIFT) - 1;

        // 起始地址落在 MTRR 范围之外，则跳过
        if (start > mtrr_end || start < mtrr_start)
        {
            continue;
        }

        // 其中有一个MTRR没有完整覆盖范围，需要更精细地划分内存类型
        if (start + size - 1 > mtrr_end)
        {
            return MEMORY_TYPE_INVALID;
        }

        current_type = select_memory_type(current_type, mtrr_physbase.fields.type);
    }
    return current_type;
}

typedef struct
{
    uint32_t msr_index;
    uint64_t base;
    uint64_t size;
} fixed_mtrr_desc_t;

void init_ept(ept_mgr_t *mgr)
{
    ept_data_t *ept = mgr->ept;
    zero_mem(ept, sizeof(ept_data_t));
    ept->pml4[0] = (ept_pml4e_t){.page_frame_number = (uint64_t)ept->pdpt >> PAGE_SHIFT, .read_access = 1, .write_access = 1, .execute_access = 1};
    for (int i = 0; i < 512; i++)
    {
        ept->pdpt[i] = (ept_pdpte_t){.page_frame_number = (uint64_t)ept->pds[i] >> PAGE_SHIFT, .read_access = 1, .write_access = 1, .execute_access = 1};
        for (int j = 0; j < 512; j++)
        {
            ept_pde_t *pde = &(ept->pds[i][j]);
            pde->large = (ept_large_pde_t){.page_frame_number = ((uint64_t)i << 9) + j, .read_access = 1, .write_access = 1, .execute_access = 1, .large_page = 1, .memory_type = MEMORY_TYPE_WRITE_BACK};
            uint64_t start = (uint64_t)pde->large.page_frame_number << 21;
            uint64_t size = 1 << 21;
            int type = get_var_mtrr_type_by_range(start, size);
            if (type == MEMORY_TYPE_INVALID)
            {
                ept_pte_t *pt = ept_split_pde(mgr, pde);
                for (int i = 0; i < 512; i++)
                {
                    pt[i].memory_type = get_var_mtrr_type_by_range(start + i * PAGE_SIZE, PAGE_SIZE);
                }
            }
            else
            {
                pde->large.memory_type = type;
            }
        }
    }

    msr_mtrr_capabilities_t mtrr_capabilities = {.all = read_msr(MSR_IA32_MTRR_CAP)};
    msr_mtrr_def_type_t mtrr_def_type = {.all = read_msr(MSR_IA32_MTRR_DEF_TYPE)};
    if (mtrr_capabilities.fields.fixed_range_supported && mtrr_def_type.fields.fixed_mtrrs_enabled)
    {
        static const fixed_mtrr_desc_t fixed_mtrr_descs[] =
            {
                {
                    MSR_IA32_MTRR_FIX_64K_00000,
                    0x0,
                    0x10000,
                },
                {
                    MSR_IA32_MTRR_FIX_16K_80000,
                    0x80000,
                    0x4000,
                },
                {
                    MSR_IA32_MTRR_FIX_16K_A0000,
                    0xA0000,
                    0x4000,
                },
                {
                    MSR_IA32_MTRR_FIX_4K_C0000,
                    0xC0000,
                    0x1000,
                },
                {
                    MSR_IA32_MTRR_FIX_4K_C8000,
                    0xC8000,
                    0x1000,
                },
                {
                    MSR_IA32_MTRR_FIX_4K_D0000,
                    0xD0000,
                    0x1000,
                },
                {
                    MSR_IA32_MTRR_FIX_4K_D8000,
                    0xD8000,
                    0x1000,
                },
                {
                    MSR_IA32_MTRR_FIX_4K_E0000,
                    0xE0000,
                    0x1000,
                },
                {
                    MSR_IA32_MTRR_FIX_4K_E8000,
                    0xE8000,
                    0x1000,
                },
                {
                    MSR_IA32_MTRR_FIX_4K_F0000,
                    0xF0000,
                    0x1000,
                },
                {
                    MSR_IA32_MTRR_FIX_4K_F8000,
                    0xF8000,
                    0x1000,
                },
            };
        ept_pde_t *pde = &ept->pds[0][0];
        ept_pte_t *pt = NULL;
        if (pde->large.large_page)
        {
            pt = ept_split_pde(mgr, pde);
        }
        else
        {
            pt = get_pt_from_pde(pde);
        }
        for (int i = 0; i < sizeof(fixed_mtrr_descs) / sizeof(fixed_mtrr_descs[0]); i++)
        {
            msr_mtrr_fixed_range_t fixed_mtrr = {.all = read_msr(fixed_mtrr_descs[i].msr_index)};
            for (int j = 0; j < sizeof(fixed_mtrr.fields.types) / sizeof(fixed_mtrr.fields.types[0]); j++)
            {
                if (fixed_mtrr.fields.types[j] != MEMORY_TYPE_INVALID)
                {
                    uint64_t start = fixed_mtrr_descs[i].base + j * fixed_mtrr_descs[i].size;
                    pt[start >> PAGE_SHIFT].memory_type = fixed_mtrr.fields.types[j];
                }
            }
        }
    }

    mgr->eptp = (eptp_t){.page_frame_number = (uint64_t)ept->pml4 >> PAGE_SHIFT, .memory_type = MEMORY_TYPE_WRITE_BACK, .page_walk_length = EPT_PAGE_WALK_LENGTH_4, .enable_access_and_dirty_flags = 1};
}

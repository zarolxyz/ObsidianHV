
#include <stdint.h>
#include "paging.h"
#include "basic_lib.h"
#include "intrin.h"

// 检查CPU是否支持1G大页
int check_pdpe1gb()
{
    uint64_t rax = 0x80000000, rcx, rdx, rbx;
    cpuid_wrapper(&rax, &rcx, &rdx, &rbx);
    // 检查是否支持0x80000001功能
    if (rax < 0x80000001)
    {
        return 0; // 不支持扩展功能，必然不支持1GB页
    }

    rax = 0x80000001;
    cpuid_wrapper(&rax, &rcx, &rdx, &rbx);

    // 步骤3：检查EDX[26]位（pdpe1gb标志）
    if (rdx & (1 << 26))
    {
        return 1; // 支持1GB大页
    }

    return 0; // 不支持1GB大页
}

static void build_identity_pdpt(pdpte_t *pdpt)
{
    zero_mem(pdpt, PAGE_SIZE);
    for (int i = 0; i < 512; i++)
    {
        pdpt[i].large = (large_pdpte_t){
            .present = 1,
            .write = 1,
            .large_page = 1,
            .page_frame_number = i,
        };
    }
}

void build_identity_pt(pt_data_t *pt)
{
    zero_mem(pt, sizeof(pt_data_t));
    build_identity_pdpt(pt->pdpt);
    pt->pml4[0] = (pml4e_t){
        .present = 1,
        .write = 1,
        .page_frame_number = (uint64_t)pt->pdpt >> PAGE_SHIFT,
    };
}
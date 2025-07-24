#include "vcpu.h"
#include "ept.h"
#include <stdint.h>
#include "basic_lib.h"
#include "vcpu.h"
#include "obhv.h"

// 分配指定对称内存块
void *obhv_alloc(obhv_t *obhv, uintptr_t size, uintptr_t alignment)
{
    uintptr_t base_addr = (uintptr_t)obhv->pool + obhv->pool_used;
    uintptr_t aligned_addr = ALIGN_UP(base_addr, alignment);
    uintptr_t real_size = ALIGN_UP(aligned_addr + size, alignment) - base_addr;
    if (real_size > obhv->pool_size - obhv->pool_used)
        return NULL;
    obhv->pool_used += real_size;
    return (void *)aligned_addr;
}

void *alloc_vcpu_shared(obhv_t *obhv)
{
    vcpu_shared_t *vcpu_shared = (vcpu_shared_t *)obhv_alloc(obhv, sizeof(vcpu_shared_t), 16);
    if (vcpu_shared == NULL)
        return NULL;
    vcpu_shared->host_pt = obhv_alloc(obhv, sizeof(host_pt_t), PAGE_SIZE);
    if (vcpu_shared->host_pt == NULL)
        return NULL;
    vcpu_shared->msr_bitmap = obhv_alloc(obhv, sizeof(msr_bitmap_t), PAGE_SIZE);
    if (vcpu_shared->msr_bitmap == NULL)
        return NULL;
    vcpu_shared->ept_mgr.ept = obhv_alloc(obhv, sizeof(ept_data_t), PAGE_SIZE);
    if (vcpu_shared->ept_mgr.ept == NULL)
        return NULL;
    return vcpu_shared;
}

void *alloc_vcpu(obhv_t *obhv)
{
    vcpu_t *vcpu = obhv_alloc(obhv, sizeof(vcpu_t), 16);
    if (vcpu == NULL)
        return NULL;
    vcpu->host_gdt = obhv_alloc(obhv, sizeof(host_gdt_t), 16);
    if (vcpu->host_gdt == NULL)
        return NULL;
    vcpu->host_tss = obhv_alloc(obhv, sizeof(host_tss_t), 16);
    if (vcpu->host_tss == NULL)
        return NULL;
    vcpu->host_stack = obhv_alloc(obhv, sizeof(host_stack_t), 16);
    if (vcpu->host_stack == NULL)
        return NULL;
    vcpu->vmxon_region = obhv_alloc(obhv, sizeof(vmxon_t), PAGE_SIZE);
    if (vcpu->vmxon_region == NULL)
        return NULL;
    vcpu->vmcs_region = obhv_alloc(obhv, sizeof(vmcs_t), PAGE_SIZE);
    if (vcpu->vmcs_region == NULL)
        return NULL;
    return vcpu;
}

int _start(obhv_t *obhv)
{
    if (obhv->vcpu_shared == NULL)
    {
        obhv->vcpu_shared = alloc_vcpu_shared(obhv);
        if (obhv->vcpu_shared == NULL)
            return -1;
        init_vcpu_shared(obhv->vcpu_shared);
    }
    vcpu_t *vcpu = alloc_vcpu(obhv);
    if (vcpu == NULL)
        return -1;
    init_vcpu(vcpu, obhv->vcpu_shared);
    int is_vm =
        capture_guest_regs(vcpu);
    if (is_vm)
    {
        return 0;
    }
    // PRINTF("Failed to capture guest registers.\n");
    launch_vcpu(vcpu);
    return -1;
}

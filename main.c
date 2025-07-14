#include "vmx.h"
#include "basic_lib.h"
#include <stdint.h>

int _start(void *mem_pool_base, uintptr_t mem_pool_size)
{
    mem_pool_t *mem_pool = mem_pool_create(mem_pool_base, mem_pool_size);
    vmx_cpu_t *vmx_cpu = vmx_create_cpu(mem_pool);
    vmx_init(vmx_cpu);
    int is_vm = vmx_capture(vmx_cpu);
    if (is_vm)
    {
        return 0;
    }
    vmx_setup(vmx_cpu);
    vmx_launch(vmx_cpu);
    return -1;
}

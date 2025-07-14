#include "vmx.h"
#include "basic_lib.h"
#include <stdint.h>

int _start(void *mem_pool_base, uintptr_t mem_pool_size)
{
    mem_pool_t *mem_pool = mem_pool_create(mem_pool_base, mem_pool_size);
    if (mem_pool == NULL)
    {
        return -1;
    }
    vmx_cpu_t *vmx_cpu = vmx_create_cpu(mem_pool);
    if (vmx_cpu == NULL)
    {
        return -1;
    }
    if (vmx_init(vmx_cpu) != 0)
    {
        return -1;
    }
    int is_vm = vmx_capture(vmx_cpu);
    if (is_vm)
    {
        return 0;
    }
    if (vmx_setup(vmx_cpu) != 0)
    {
        return -1;
    }
    vmx_launch(vmx_cpu);
    PRINTF("VMX launch failed: 0x%x\n", vmx_get_instruction_error_code());
    return -1;
}

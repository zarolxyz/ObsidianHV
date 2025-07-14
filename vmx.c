#include "vmx.h"
#include "intrin.h"
#include "basic_lib.h"

#define VMX_AR_UNUSABLE 0x10000

// 判断CPU是否支持VMX虚拟化
static int vmx_check_cpuid()
{
  uint64_t rax = 0x1, rbx, rcx = 0, rdx;
  cpuid_wrapper(&rax, &rcx, &rdx, &rbx);

  const uint8_t VMX_BIT = 5; // ECX寄存器的第5位表示VMX支持[6,8](@ref)
  return (rcx >> VMX_BIT) & 1;
}

uint64_t vmx_ajust_cr0(uint64_t value)
{
  value &= read_msr(MSR_IA32_VMX_CR0_FIXED1);
  value |= read_msr(MSR_IA32_VMX_CR0_FIXED0);
  return value;
}

uint64_t vmx_ajust_cr4(uint64_t value)
{
  value &= read_msr(MSR_IA32_VMX_CR4_FIXED1);
  value |= read_msr(MSR_IA32_VMX_CR4_FIXED0);
  return value;
}

int msr_bitmap_set_read(msr_bitmap_t *msr_bitmap, uint32_t index)
{
  if (!is_valid_msr(index))
    return -1;

  if (is_high_msr(index))
  {
    // 计算高位MSR相对基址的偏移量
    uint32_t offset = index - HIGH_MSR_BASE;
    bitmap_setbit(msr_bitmap->read_high, offset);
  }
  else
  {
    bitmap_setbit(msr_bitmap->read_low, index);
  }
  return 0;
}

int msr_bitmap_set_write(msr_bitmap_t *msr_bitmap, uint32_t index)
{
  if (!is_valid_msr(index))
    return -1;

  if (is_high_msr(index))
  {
    // 计算高位MSR相对基址的偏移量
    uint32_t offset = index - HIGH_MSR_BASE;
    bitmap_setbit(msr_bitmap->write_high, offset);
  }
  else
  {
    bitmap_setbit(msr_bitmap->write_low, index);
  }
  return 0;
}

void init_msr_bitmap(msr_bitmap_t *msr_bitmap)
{
  zero_mem(msr_bitmap, sizeof(msr_bitmap_t));
}

vmx_cpu_t *vmx_create_cpu(mem_pool_t *mem_pool)
{
  vcpu_t *vcpu = vcpu_create(mem_pool);
  vmx_cpu_t *vmx_cpu = vcpu_alloc_aligned_mem(vcpu, sizeof(vmx_cpu_t));

  if (vcpu == NULL || vmx_cpu == NULL)
  {
    PRINTF("Failed to allocate VMX CPU structure\n");
    return NULL;
  }
  vmx_cpu->vcpu = vcpu;
  return vmx_cpu;
}

int vmx_init(vmx_cpu_t *vmx_cpu)
{
  if (vcpu_init(vmx_cpu->vcpu) != 0)
    return -1;
  vmx_cpu->vmxon_region = vcpu_alloc_page(vmx_cpu->vcpu);
  vmx_cpu->vmcs_region = vcpu_alloc_page(vmx_cpu->vcpu);
  vmx_cpu->msr_bitmap = vcpu_alloc_page(vmx_cpu->vcpu);
  if (vmx_cpu->vmxon_region == NULL ||
      vmx_cpu->vmcs_region == NULL ||
      vmx_cpu->msr_bitmap == NULL)
  {
    PRINTF("Failed to allocate VMX region\n");
    return -1;
  }
  return 0;
}

uint32_t vmx_adjust_control_value(uint32_t msr_index,
                                  uint32_t control_value)
{
  uint64_t msr_value = read_msr(msr_index);
  uint32_t msr_high = msr_value >> 32;
  uint32_t msr_low = msr_value & 0xFFFFFFFF;
  return (control_value | msr_low) & msr_high;
}

static int vmx_set_control_field(uint32_t field, uint64_t control)
{
  uint32_t msr_index = 0;
  switch (field)
  {
  case VM_ENTRY_CONTROLS:
    msr_index = MSR_IA32_VMX_TRUE_ENTRY_CTLS;
    break;
  case VM_EXIT_CONTROLS:
    msr_index = MSR_IA32_VMX_TRUE_EXIT_CTLS;
    break;
  case PIN_BASED_VM_EXEC_CONTROL:
    msr_index = MSR_IA32_VMX_TRUE_PINBASED_CTLS;
    break;
  case CPU_BASED_VM_EXEC_CONTROL:
    msr_index = MSR_IA32_VMX_TRUE_PROCBASED_CTLS;
    break;
  case SECONDARY_VM_EXEC_CONTROL:
    msr_index = MSR_IA32_VMX_PROCBASED_CTLS2;
    break;
  default:
    return -1; // 不支持的字段
  }
  return vmwrite(field, vmx_adjust_control_value(msr_index, control));
}

static uint32_t vmx_convert_access_rights(uint32_t access_rights)
{
  if (access_rights == 0)
    return VMX_AR_UNUSABLE;
  return (access_rights >> 8) & 0b1111000011111111;
}

int vmx_setup_vmcs(vmx_cpu_t *vmx_cpu)
{
  PRINTF("Setup VMCS...\n");
  int error = 0;
  error |= vmwrite(VMCS_LINK_POINTER, UINT64_MAX); // 禁用VMCS链接
  error |= vmwrite(VMCS_LINK_POINTER_HIGH, UINT64_MAX);
  error |= vmwrite(VIRTUAL_PROCESSOR_ID, 1);
  error |= vmwrite(CR3_TARGET_COUNT, 0);
  error |= vmwrite(TSC_OFFSET, 0);
  error |= vmwrite(TSC_OFFSET_HIGH, 0);
  error |= vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
  error |= vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);
  error |= vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
  error |= vmwrite(VM_EXIT_MSR_LOAD_ADDR, 0);
  error |= vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
  error |= vmwrite(VM_EXIT_MSR_STORE_ADDR, 0);
  error |= vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
  error |= vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

  error |= vmx_set_control_field(CPU_BASED_VM_EXEC_CONTROL,
                                 CPU_BASED_ACTIVATE_MSR_BITMAP |
                                     CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
  error |= vmx_set_control_field(SECONDARY_VM_EXEC_CONTROL,
                                 SECONDARY_EXEC_ENABLE_INVPCID |
                                     SECONDARY_EXEC_ENABLE_RDTSCP |
                                     SECONDARY_EXEC_ENABLE_XSAVES_XSTORS);
  error |= vmx_set_control_field(PIN_BASED_VM_EXEC_CONTROL, 0);
  error |= vmx_set_control_field(VM_ENTRY_CONTROLS, VM_ENTRY_IA32E_MODE_GUEST);
  error |= vmx_set_control_field(VM_EXIT_CONTROLS, VM_EXIT_IA32E_MODE_HOST);

  error |= vmwrite(MSR_BITMAP, (uint64_t)vmx_cpu->msr_bitmap);

  error |= vmwrite(EXCEPTION_BITMAP, 0);

  gdtr_t gdtr;
  idtr_t idtr;
  read_gdtr((uint64_t)&gdtr);
  read_idtr((uint64_t)&idtr);

  uint64_t cr0 = read_cr0();
  uint64_t cr3 = read_cr3();
  uint64_t cr4 = read_cr4();

  uint16_t cs = read_cs();
  uint16_t ds = read_ds();
  uint16_t es = read_es();
  uint16_t ss = read_ss();
  uint16_t fs = read_fs();
  uint16_t gs = read_gs();

  error |= vmwrite(GUEST_CR0, cr0);
  error |= vmwrite(GUEST_CR3, cr3);
  error |= vmwrite(GUEST_CR4, cr4);

  error |= vmwrite(GUEST_DR7, read_dr7());

  error |= vmwrite(GUEST_RSP, (uint64_t)vmx_cpu->vcpu->regs.rsp);
  error |= vmwrite(GUEST_RIP, (uint64_t)vmx_cpu->vcpu->regs.rip);
  error |= vmwrite(GUEST_RFLAGS, read_rflags());

  // 写入CS、DS、ES、SS、FS、GS、LDTR和TR寄存器的选择子和描述符信息
  error |= vmwrite(GUEST_CS_SELECTOR, cs);
  error |= vmwrite(GUEST_CS_BASE, 0);
  error |= vmwrite(GUEST_CS_LIMIT, UINT64_MAX);
  error |= vmwrite(GUEST_CS_AR_BYTES,
                   vmx_convert_access_rights(read_cs_access_rights()));

  error |= vmwrite(GUEST_DS_SELECTOR, ds);
  error |= vmwrite(GUEST_DS_BASE, 0);
  error |= vmwrite(GUEST_DS_LIMIT, UINT64_MAX);
  error |= vmwrite(GUEST_DS_AR_BYTES,
                   vmx_convert_access_rights(read_ds_access_rights()));

  error |= vmwrite(GUEST_ES_SELECTOR, es);
  error |= vmwrite(GUEST_ES_BASE, 0);
  error |= vmwrite(GUEST_ES_LIMIT, UINT64_MAX);
  error |= vmwrite(GUEST_ES_AR_BYTES,
                   vmx_convert_access_rights(read_es_access_rights()));

  error |= vmwrite(GUEST_SS_SELECTOR, ss);
  error |= vmwrite(GUEST_SS_BASE, 0);
  error |= vmwrite(GUEST_SS_LIMIT, UINT64_MAX);
  error |= vmwrite(GUEST_SS_AR_BYTES,
                   vmx_convert_access_rights(read_ss_access_rights()));

  error |= vmwrite(GUEST_FS_SELECTOR, fs);
  error |= vmwrite(GUEST_FS_BASE, 0);
  error |= vmwrite(GUEST_FS_LIMIT, UINT64_MAX);
  error |= vmwrite(GUEST_FS_AR_BYTES,
                   vmx_convert_access_rights(read_fs_access_rights()));

  error |= vmwrite(GUEST_GS_SELECTOR, gs);
  error |= vmwrite(GUEST_GS_BASE, 0);
  error |= vmwrite(GUEST_GS_LIMIT, UINT64_MAX);
  error |= vmwrite(GUEST_GS_AR_BYTES,
                   vmx_convert_access_rights(read_gs_access_rights()));

  error |= vmwrite(GUEST_LDTR_SELECTOR, 0);
  error |= vmwrite(GUEST_LDTR_LIMIT, 0);
  error |= vmwrite(GUEST_LDTR_AR_BYTES, VMX_AR_UNUSABLE);

  error |= vmwrite(GUEST_TR_SELECTOR, 0);
  error |= vmwrite(GUEST_TR_BASE, 0);
  error |= vmwrite(GUEST_TR_LIMIT, TSS_SIZE - 1);
  error |= vmwrite(GUEST_TR_AR_BYTES, vmx_convert_access_rights(TSS_AR));

  error |= vmwrite(GUEST_GDTR_BASE, gdtr.base);
  error |= vmwrite(GUEST_GDTR_LIMIT, gdtr.limit);
  error |= vmwrite(GUEST_IDTR_BASE, idtr.base);
  error |= vmwrite(GUEST_IDTR_LIMIT, idtr.limit);

  error |= vmwrite(HOST_CR0, cr0);
  error |= vmwrite(HOST_CR3, (uint64_t)vmx_cpu->vcpu->host_pml4);
  error |= vmwrite(HOST_CR4, cr4);

  error |= vmwrite(HOST_CS_SELECTOR, HOST_GDT_CS & 0xfff8);
  error |= vmwrite(HOST_DS_SELECTOR, 0);
  error |= vmwrite(HOST_ES_SELECTOR, 0);
  error |= vmwrite(HOST_SS_SELECTOR, 0);
  error |= vmwrite(HOST_FS_SELECTOR, 0);
  error |= vmwrite(HOST_GS_SELECTOR, 0);

  error |= vmwrite(HOST_FS_BASE, 0);
  error |= vmwrite(HOST_GS_BASE, 0);

  error |= vmwrite(HOST_TR_SELECTOR, HOST_GDT_TR & 0xfff8);

  error |= vmwrite(HOST_TR_BASE, (uint64_t)vmx_cpu->vcpu->host_tss);

  error |= vmwrite(HOST_GDTR_BASE, (uint64_t)vmx_cpu->vcpu->host_gdt);
  error |= vmwrite(HOST_IDTR_BASE, UINT64_MAX);

  error |= vmwrite(CR0_READ_SHADOW, cr0);
  error |= vmwrite(CR4_READ_SHADOW, cr4 & ~CR4_VMXE_MASK);

  error |= vmwrite(HOST_RSP, (uint64_t)vmx_cpu->vcpu->host_rsp);
  error |= vmwrite(HOST_RIP, (uint64_t)vmx_get_exit_handler());

  error |= vmwrite(CR0_GUEST_HOST_MASK, 0);
  error |= vmwrite(CR4_GUEST_HOST_MASK, CR4_VMXE_MASK);
  return error;
}

int vmx_enter_root(vmx_cpu_t *vmx_cpu)
{
  PRINTF("Enter VMX root operation mode...\n");

  uint64_t vmx_basic = read_msr(MSR_IA32_VMX_BASIC);
  uint64_t feature_control = read_msr(MSR_IA32_FEATURE_CONTROL);

  if (!vmx_check_cpuid())
  {
    PRINTF("CPU does not support Intel virtualization features\n");
    return -1;
  }
  if (!(vmx_basic & VMX_BASIC_TRUE_CONTROLS))
  {
    PRINTF("CPU does not support VMX true controls\n");
    return -1;
  }
  if (!(feature_control & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX))
  {
    PRINTF(
        "CPU virtualization is locked\n");
    return -1;
  }

  zero_mem(vmx_cpu->vmxon_region, sizeof(vmxon_t));
  zero_mem(vmx_cpu->vmcs_region, sizeof(vmcs_t));
  vmx_cpu->vmxon_region->revision_id = vmx_basic & VMX_BASIC_REVISION_MASK;
  vmx_cpu->vmcs_region->revision_id = vmx_basic & VMX_BASIC_REVISION_MASK;

  uint64_t cr0 = read_cr0();
  uint64_t cr4 = read_cr4();
  cr0 = vmx_ajust_cr0(cr0);
  cr4 = vmx_ajust_cr4(cr4);
  write_cr0(cr0);
  write_cr4(cr4);

  uint64_t addr = (uint64_t)(vmx_cpu->vmxon_region);
  if (vmxon(&addr) != 0)
  {
    PRINTF("Failed to enter VMX operation mode\n");
    return -1;
  }
  addr = (uint64_t)(vmx_cpu->vmcs_region);
  if (vmclear(&addr) != 0)
  {
    vmxoff();
    PRINTF("Failed to clear VMCS\n");
    return -1;
  }
  addr = (uint64_t)(vmx_cpu->vmcs_region);
  if (vmptrld(&addr) != 0)
  {
    vmxoff();
    PRINTF("Failed to load VMCS\n");
    return -1;
  }
  return 0;
}

int vmx_setup(vmx_cpu_t *vmx_cpu)
{
  vmx_enter_root(vmx_cpu);

  init_msr_bitmap(vmx_cpu->msr_bitmap);
  msr_bitmap_set_read(vmx_cpu->msr_bitmap, MSR_IA32_FEATURE_CONTROL);
  vcpu_host_push(vmx_cpu->vcpu, (uint64_t)vmx_cpu);

  if (vmx_setup_vmcs(vmx_cpu) != 0)
  {
    vmxoff();
    PRINTF("Failed to setup VMCS\n");
    return -1;
  }
  return 0;
}

void vmx_dump_host_state(void)
{
  uint64_t value = 0;
  vmread(HOST_CR0, &value);
  PRINTF("HOST CR0: %x\n", value);
  vmread(HOST_CR3, &value);
  PRINTF("HOST CR3: %x\n", value);
  vmread(HOST_CR4, &value);
  PRINTF("HOST CR4: %x\n", value);
  vmread(HOST_RSP, &value);
  PRINTF("HOST RSP: %x\n", value);
  vmread(HOST_RIP, &value);
  PRINTF("HOST RIP: %x\n", value);
  vmread(HOST_CS_SELECTOR, &value);
  PRINTF("HOST CS: %x\n", value);
  vmread(HOST_ES_SELECTOR, &value);
  PRINTF("HOST ES: %x\n", value);
  vmread(HOST_SS_SELECTOR, &value);
  PRINTF("HOST SS: %x\n", value);
  vmread(HOST_DS_SELECTOR, &value);
  PRINTF("HOST DS: %x\n", value);
  vmread(HOST_FS_SELECTOR, &value);
  PRINTF("HOST FS: %x\n", value);
  vmread(HOST_GS_SELECTOR, &value);
  PRINTF("HOST GS: %x\n", value);
  vmread(HOST_TR_SELECTOR, &value);
  PRINTF("HOST TR: %x\n", value);
  vmread(HOST_FS_BASE, &value);
  PRINTF("HOST FS BASE: %x\n", value);
  vmread(HOST_GS_BASE, &value);
  PRINTF("HOST GS BASE: %x\n", value);
  vmread(HOST_TR_BASE, &value);
  PRINTF("HOST TR BASE: %x\n", value);
  vmread(HOST_GDTR_BASE, &value);
  PRINTF("HOST GDTR BASE: %x\n", value);
  vmread(HOST_IDTR_BASE, &value);
  PRINTF("HOST IDTR BASE: %x\n", value);
}

void vmx_dump_guest_state(void)
{
  uint64_t value = 0;
  vmread(GUEST_CR0, &value);
  PRINTF("GUEST CR0: %x\n", value);
  vmread(GUEST_CR3, &value);
  PRINTF("GUEST CR3: %x\n", value);
  vmread(GUEST_CR4, &value);
  PRINTF("GUEST CR4: %x\n", value);
  vmread(GUEST_RSP, &value);
  PRINTF("GUEST RSP: %x\n", value);
  vmread(GUEST_RIP, &value);
  PRINTF("GUEST RIP: %x\n", value);
  vmread(GUEST_RFLAGS, &value);
  PRINTF("GUEST RFLAGS: %x\n", value);
  vmread(GUEST_CS_SELECTOR, &value);
  PRINTF("GUEST CS: %x\n", value);
  vmread(GUEST_ES_SELECTOR, &value);
  PRINTF("GUEST ES: %x\n", value);
  vmread(GUEST_SS_SELECTOR, &value);
  PRINTF("GUEST SS: %x\n", value);
  vmread(GUEST_DS_SELECTOR, &value);
  PRINTF("GUEST DS: %x\n", value);
  vmread(GUEST_FS_SELECTOR, &value);
  PRINTF("GUEST FS: %x\n", value);
  vmread(GUEST_GS_SELECTOR, &value);
  PRINTF("GUEST GS: %x\n", value);
  vmread(GUEST_TR_SELECTOR, &value);
  PRINTF("GUEST TR: %x\n", value);
  vmread(GUEST_CS_BASE, &value);
  PRINTF("GUEST CS BASE: %x\n", value);
  vmread(GUEST_ES_BASE, &value);
  PRINTF("GUEST ES BASE: %x\n", value);
  vmread(GUEST_SS_BASE, &value);
  PRINTF("GUEST SS BASE: %x\n", value);
  vmread(GUEST_DS_BASE, &value);
  PRINTF("GUEST DS BASE: %x\n", value);
  vmread(GUEST_FS_BASE, &value);
  PRINTF("GUEST FS BASE: %x\n", value);
  vmread(GUEST_GS_BASE, &value);
  PRINTF("GUEST GS BASE: %x\n", value);
  vmread(GUEST_GDTR_BASE, &value);
  PRINTF("GUEST GDTR BASE: %x\n", value);
  vmread(GUEST_IDTR_BASE, &value);
  PRINTF("GUEST IDTR BASE: %x\n", value);
  vmread(GUEST_TR_BASE, &value);
  PRINTF("GUEST TR BASE: %x\n", value);
  vmread(GUEST_CS_LIMIT, &value);
  PRINTF("GUEST CS LIMIT: %x\n", value);
  vmread(GUEST_ES_LIMIT, &value);
  PRINTF("GUEST ES LIMIT: %x\n", value);
  vmread(GUEST_SS_LIMIT, &value);
  PRINTF("GUEST SS LIMIT: %x\n", value);
  vmread(GUEST_DS_LIMIT, &value);
  PRINTF("GUEST DS LIMIT: %x\n", value);
  vmread(GUEST_FS_LIMIT, &value);
  PRINTF("GUEST FS LIMIT: %x\n", value);
  vmread(GUEST_GS_LIMIT, &value);
  PRINTF("GUEST GS LIMIT: %x\n", value);
  vmread(GUEST_TR_LIMIT, &value);
  PRINTF("GUEST TR LIMIT: %x\n", value);
  vmread(GUEST_CS_AR_BYTES, &value);
  PRINTF("GUEST CS AR_BYTES: %x\n", value);
  vmread(GUEST_ES_AR_BYTES, &value);
  PRINTF("GUEST ES AR_BYTES: %x\n", value);
  vmread(GUEST_SS_AR_BYTES, &value);
  PRINTF("GUEST SS AR_BYTES: %x\n", value);
  vmread(GUEST_DS_AR_BYTES, &value);
  PRINTF("GUEST DS AR_BYTES: %x\n", value);
  vmread(GUEST_FS_AR_BYTES, &value);
  PRINTF("GUEST FS AR_BYTES: %x\n", value);
  vmread(GUEST_GS_AR_BYTES, &value);
  PRINTF("GUEST GS AR_BYTES: %x\n", value);
  vmread(GUEST_TR_AR_BYTES, &value);
  PRINTF("GUEST TR AR_BYTES: %x\n", value);
}

uint64_t vmx_get_instruction_error_code(void)
{
  uint64_t value = 0;
  ASSERT(vmread(VM_INSTRUCTION_ERROR, &value) == 0);
  return value;
}

int vmx_inject_interruption(int type, int vector)
{
  vm_entry_interruption_info_t info = {0};
  info.fields.valid = 1;
  info.fields.vector = vector;
  info.fields.interruption_type = type;
  info.fields.deliver_error_code = 0;
  return vmwrite(VM_ENTRY_INTR_INFO_FIELD, info.all);
}

int vmx_inject_interruption_error_code(int type, int vector, uint32_t error_code)
{
  vm_entry_interruption_info_t info = {0};
  info.fields.valid = 1;
  info.fields.vector = vector;
  info.fields.interruption_type = type;
  info.fields.deliver_error_code = 1;
  return vmwrite(VM_ENTRY_INTR_INFO_FIELD, info.all) | vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
}

static void advance_rip()
{
  uint64_t instruction_len = 0;
  ASSERT(vmread(VM_EXIT_INSTRUCTION_LEN, &instruction_len) == 0);
  uint64_t rip = 0;
  ASSERT(vmread(GUEST_RIP, &rip) == 0);
  rip += instruction_len;
  ASSERT(vmwrite(GUEST_RIP, rip) == 0);
}

static void inject_ud()
{
  ASSERT(vmx_inject_interruption(VMX_INTR_TYPE_HWEXCEPTION, EXCEPTION_UD) == 0);
}

static void inject_gp(uint32_t error_code)
{
  ASSERT(vmx_inject_interruption_error_code(VMX_INTR_TYPE_HWEXCEPTION, EXCEPTION_GP, error_code) == 0);
}

static void emulate_rdmsr(regs_t *regs)
{
  if (!is_valid_msr(regs->rcx))
  {
    PRINTF("Invalid MSR access: %x\n", regs->rcx);
    inject_gp(0);
    return;
  }
  uint64_t value = read_msr(regs->rcx);
  if (regs->rcx == MSR_IA32_FEATURE_CONTROL)
  {
    value &= IA32_FEATURE_CONTROL_MSR_LOCK;
    value &= ~(IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX);
  }
  regs->rax = value >> 32;
  regs->rdx = value & 0xffffffff;
  advance_rip();
}

static void emulate_wrmsr(regs_t *regs)
{
  if (!is_valid_msr(regs->rcx))
  {
    PRINTF("Invalid MSR access: %x\n", regs->rcx);
    inject_gp(0);
    return;
  }
  uint64_t value = regs->rax << 32 | regs->rdx;
  write_msr(regs->rcx, value);
  advance_rip();
}

static void emulate_init(regs_t *regs)
{
  int error = 0;

  error |= vmwrite(CR0_READ_SHADOW, 0x10);
  error |= vmwrite(GUEST_CR3, 0);
  error |= vmwrite(GUEST_CR4, 0);
  error |= vmwrite(CR4_READ_SHADOW, 0);

  error |= vmwrite(GUEST_CR0, vmx_ajust_cr0(0x10));
  error |= vmwrite(GUEST_CR4, vmx_ajust_cr4(0));

  error |= vmwrite(GUEST_CS_SELECTOR, 0xf000);
  error |= vmwrite(GUEST_CS_BASE, 0xffff0000);
  error |= vmwrite(GUEST_CS_LIMIT, 0xffff);
  error |= vmwrite(GUEST_CS_AR_BYTES, 0x9b);
  error |= vmwrite(GUEST_SS_SELECTOR, 0);
  error |= vmwrite(GUEST_SS_BASE, 0);
  error |= vmwrite(GUEST_SS_LIMIT, 0xffff);
  error |= vmwrite(GUEST_SS_AR_BYTES, 0x93);
  error |= vmwrite(GUEST_DS_SELECTOR, 0);
  error |= vmwrite(GUEST_DS_BASE, 0);
  error |= vmwrite(GUEST_DS_LIMIT, 0xffff);
  error |= vmwrite(GUEST_DS_AR_BYTES, 0x93);
  error |= vmwrite(GUEST_ES_SELECTOR, 0);
  error |= vmwrite(GUEST_ES_BASE, 0);
  error |= vmwrite(GUEST_ES_LIMIT, 0xffff);
  error |= vmwrite(GUEST_ES_AR_BYTES, 0x93);
  error |= vmwrite(GUEST_FS_SELECTOR, 0);
  error |= vmwrite(GUEST_FS_BASE, 0);
  error |= vmwrite(GUEST_FS_LIMIT, 0xffff);
  error |= vmwrite(GUEST_FS_AR_BYTES, 0x93);
  error |= vmwrite(GUEST_GS_SELECTOR, 0);
  error |= vmwrite(GUEST_GS_BASE, 0);
  error |= vmwrite(GUEST_GS_LIMIT, 0xffff);
  error |= vmwrite(GUEST_GS_AR_BYTES, 0x93);
  error |= vmwrite(GUEST_TR_SELECTOR, 0);
  error |= vmwrite(GUEST_TR_BASE, 0);
  error |= vmwrite(GUEST_TR_LIMIT, 0xffff);
  error |= vmwrite(GUEST_TR_AR_BYTES, 0x8b);
  error |= vmwrite(GUEST_LDTR_SELECTOR, 0);
  error |= vmwrite(GUEST_LDTR_BASE, 0);
  error |= vmwrite(GUEST_LDTR_LIMIT, 0xffff);
  error |= vmwrite(GUEST_LDTR_AR_BYTES, 0x82);

  error |= vmwrite(GUEST_GDTR_BASE, 0);
  error |= vmwrite(GUEST_GDTR_LIMIT, 0xffff);
  error |= vmwrite(GUEST_IDTR_BASE, 0);
  error |= vmwrite(GUEST_IDTR_LIMIT, 0xffff);

  error |= vmwrite(GUEST_DR7, 0x400);

  uint64_t entry_control = 0;
  error |= vmread(VM_ENTRY_CONTROLS, &entry_control);
  entry_control &= ~VM_ENTRY_IA32E_MODE_GUEST;
  error |= vmwrite(VM_ENTRY_CONTROLS, entry_control);

  ASSERT(error == 0);

  vcpu_emulate_init(regs);
  error |= vmwrite(GUEST_RFLAGS, 2);
  error |= vmwrite(GUEST_RIP, regs->rip);
  error |= vmwrite(GUEST_RSP, regs->rsp);

  error |= vmwrite(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_WAIT_SIPI);

  ASSERT(error == 0);
}

static void emulate_sipi()
{
  uint64_t vector = 0;
  ASSERT(vmread(EXIT_QUALIFICATION, &vector) == 0);
  ASSERT(vmwrite(GUEST_CS_SELECTOR, vector << 8) == 0);
  ASSERT(vmwrite(GUEST_CS_BASE, vector << 12) == 0);
  ASSERT(vmwrite(GUEST_RIP, 0) == 0);
  ASSERT(vmwrite(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE) == 0);
}

void vmx_exit_handler(vmx_cpu_t *vmx_cpu)
{
  vcpu_t *vcpu = vmx_cpu->vcpu;
  regs_t *regs = &vcpu->regs;
  uint64_t exit_reason = 0;
  ASSERT(vmread(VM_EXIT_REASON, &exit_reason) == 0);
  PRINTF("VM_EXIT_REASON: 0x%x\n", exit_reason);
  switch (exit_reason)
  {
  case EXIT_REASON_INVD:
    vcpu_emulate_invd(regs);
    advance_rip();
    break;
  case EXIT_REASON_CPUID:
    vcpu_emulate_cpuid(regs);
    advance_rip();
    break;
  case EXIT_REASON_XSETBV:
    vcpu_emulate_xsetbv(regs);
    advance_rip();
    break;
  case EXIT_REASON_VMCALL:
  case EXIT_REASON_VMCLEAR:
  case EXIT_REASON_VMLAUNCH:
  case EXIT_REASON_VMPTRLD:
  case EXIT_REASON_VMPTRST:
  case EXIT_REASON_VMREAD:
  case EXIT_REASON_VMRESUME:
  case EXIT_REASON_VMWRITE:
  case EXIT_REASON_VMXOFF:
  case EXIT_REASON_VMXON:
    inject_ud();
    break;
  case EXIT_REASON_MSR_READ:
    emulate_rdmsr(regs);
    break;
  case EXIT_REASON_MSR_WRITE:
    emulate_wrmsr(regs);
    break;
  case EXIT_REASON_INIT:
    emulate_init(regs);
    break;
  case EXIT_REASON_SIPI:
    emulate_sipi();
    break;
  default:
    PRINTF("Unhandled VM EXIT: 0x%x\n", exit_reason);
    goto err;
    break;
  }
  PRINTF("VM EXIT handled successfully\n");
  return;
err:
  PRINTF("Failed to handle VM EXIT\n");
  PANIC();
}

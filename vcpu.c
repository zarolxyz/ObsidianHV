#include "vcpu.h"
#include "basic_lib.h"
#include "intrin.h"

#define HOST_GDT_CS 0x08
#define HOST_GDT_TR 0x10

#define VCPU_VPID 1

// 打印时带上VCPU编号
#define VCPU_PRINTF(vcpu, fmt, ...) PRINTF("VCPU%d: " fmt, vcpu->vcpu_id, ##__VA_ARGS__)

int init_vcpu_shared(vcpu_shared_t *vcpu_shared)
{
  if (!check_pdpe1gb())
  {
    PRINTF("CPU does not support pdpe1gb feature.\n");
    return -1;
  }
  init_msr_bitmap(vcpu_shared->msr_bitmap);
  msr_bitmap_set_read(vcpu_shared->msr_bitmap, MSR_IA32_FEATURE_CONTROL);
  build_identity_pt(vcpu_shared->host_pt);
  init_ept(&vcpu_shared->ept_mgr);

  vcpu_shared->vcpu_num = 0;

  return 0;
}

void dump_host_state(void)
{
  PRINTF("HOST CR0: %x\n", vmread(HOST_CR0));
  PRINTF("HOST CR3: %x\n", vmread(HOST_CR3));
  PRINTF("HOST CR4: %x\n", vmread(HOST_CR4));
  PRINTF("HOST RSP: %x\n", vmread(HOST_RSP));
  PRINTF("HOST RIP: %x\n", vmread(HOST_RIP));
  PRINTF("HOST ES: %x\n", vmread(HOST_ES_SELECTOR));
  PRINTF("HOST CS: %x\n", vmread(HOST_CS_SELECTOR));
  PRINTF("HOST SS: %x\n", vmread(HOST_SS_SELECTOR));
  PRINTF("HOST DS: %x\n", vmread(HOST_DS_SELECTOR));
  PRINTF("HOST FS: %x\n", vmread(HOST_FS_SELECTOR));
  PRINTF("HOST GS: %x\n", vmread(HOST_GS_SELECTOR));
  PRINTF("HOST TR: %x\n", vmread(HOST_TR_SELECTOR));
  PRINTF("HOST FS BASE: %x\n", vmread(HOST_FS_BASE));
  PRINTF("HOST GS BASE: %x\n", vmread(HOST_GS_BASE));
  PRINTF("HOST TR BASE: %x\n", vmread(HOST_TR_BASE));
  PRINTF("HOST GDTR BASE: %x\n", vmread(HOST_GDTR_BASE));
  PRINTF("HOST IDTR BASE: %x\n", vmread(HOST_IDTR_BASE));
}

void dump_guest_state(void)
{
  PRINTF("GUEST CR0: %x\n", vmread(GUEST_CR0));
  PRINTF("GUEST CR3: %x\n", vmread(GUEST_CR3));
  PRINTF("GUEST CR4: %x\n", vmread(GUEST_CR4));
  PRINTF("GUEST DR7: %x\n", vmread(GUEST_DR7));
  PRINTF("GUEST RSP: %x\n", vmread(GUEST_RSP));
  PRINTF("GUEST RIP: %x\n", vmread(GUEST_RIP));
  PRINTF("GUEST RFLAGS: %x\n", vmread(GUEST_RFLAGS));
  PRINTF("GUEST ES: %x\n", vmread(GUEST_ES_SELECTOR));
  PRINTF("GUEST ES BASE: %x\n", vmread(GUEST_ES_BASE));
  PRINTF("GUEST ES LIMIT: %x\n", vmread(GUEST_ES_LIMIT));
  PRINTF("GUEST ES AR: %x\n", vmread(GUEST_ES_AR_BYTES));
  PRINTF("GUEST CS: %x\n", vmread(GUEST_CS_SELECTOR));
  PRINTF("GUEST CS BASE: %x\n", vmread(GUEST_CS_BASE));
  PRINTF("GUEST CS LIMIT: %x\n", vmread(GUEST_CS_LIMIT));
  PRINTF("GUEST CS AR: %x\n", vmread(GUEST_CS_AR_BYTES));
  PRINTF("GUEST SS: %x\n", vmread(GUEST_SS_SELECTOR));
  PRINTF("GUEST SS BASE: %x\n", vmread(GUEST_SS_BASE));
  PRINTF("GUEST SS LIMIT: %x\n", vmread(GUEST_SS_LIMIT));
  PRINTF("GUEST SS AR: %x\n", vmread(GUEST_SS_AR_BYTES));
  PRINTF("GUEST DS: %x\n", vmread(GUEST_DS_SELECTOR));
  PRINTF("GUEST DS BASE: %x\n", vmread(GUEST_DS_BASE));
  PRINTF("GUEST DS LIMIT: %x\n", vmread(GUEST_DS_LIMIT));
  PRINTF("GUEST DS AR: %x\n", vmread(GUEST_DS_AR_BYTES));
  PRINTF("GUEST FS: %x\n", vmread(GUEST_FS_SELECTOR));
  PRINTF("GUEST FS BASE: %x\n", vmread(GUEST_FS_BASE));
  PRINTF("GUEST FS LIMIT: %x\n", vmread(GUEST_FS_LIMIT));
  PRINTF("GUEST FS AR: %x\n", vmread(GUEST_FS_AR_BYTES));
  PRINTF("GUEST GS: %x\n", vmread(GUEST_GS_SELECTOR));
  PRINTF("GUEST GS BASE: %x\n", vmread(GUEST_GS_BASE));
  PRINTF("GUEST GS LIMIT: %x\n", vmread(GUEST_GS_LIMIT));
  PRINTF("GUEST GS AR: %x\n", vmread(GUEST_GS_AR_BYTES));
  PRINTF("GUEST LDTR: %x\n", vmread(GUEST_LDTR_SELECTOR));
  PRINTF("GUEST LDTR BASE: %x\n", vmread(GUEST_LDTR_BASE));
  PRINTF("GUEST LDTR LIMIT: %x\n", vmread(GUEST_LDTR_LIMIT));
  PRINTF("GUEST LDTR AR: %x\n", vmread(GUEST_LDTR_AR_BYTES));
  PRINTF("GUEST TR: %x\n", vmread(GUEST_TR_SELECTOR));
  PRINTF("GUEST TR BASE: %x\n", vmread(GUEST_TR_BASE));
  PRINTF("GUEST TR LIMIT: %x\n", vmread(GUEST_TR_LIMIT));
  PRINTF("GUEST TR AR: %x\n", vmread(GUEST_TR_AR_BYTES));
  PRINTF("GUEST GDTR BASE: %x\n", vmread(GUEST_GDTR_BASE));
  PRINTF("GUEST GDTR LIMIT: %x\n", vmread(GUEST_GDTR_LIMIT));
  PRINTF("GUEST IDTR BASE: %x\n", vmread(GUEST_IDTR_BASE));
  PRINTF("GUEST IDTR LIMIT: %x\n", vmread(GUEST_IDTR_LIMIT));
  PRINTF("GUEST DEBUGCTL: %x\n", vmread(GUEST_IA32_DEBUGCTL));
  PRINTF("GUEST ACTIVITY STATE: %x\n", vmread(GUEST_ACTIVITY_STATE));
}

void init_vcpu(vcpu_t *vcpu, vcpu_shared_t *shared)
{
  vcpu->shared = shared;
  zero_mem(vcpu->host_tss, sizeof(tss64_t));
  build_gdt(vcpu->host_gdt, vcpu->host_tss);
  vcpu->host_stack->vcpu_pointer = (uint64_t)vcpu;
  vcpu->vcpu_id = shared->vcpu_num;
  shared->vcpu_num++;
}

uintptr_t get_vm_exit_handler_asm();

static void setup_vmcs(vcpu_t *vcpu)
{
  vmx_set_control_field(CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
  vmx_set_control_field(SECONDARY_VM_EXEC_CONTROL, SECONDARY_EXEC_ENABLE_INVPCID | SECONDARY_EXEC_ENABLE_RDTSCP | SECONDARY_EXEC_ENABLE_XSAVES_XSTORS | SECONDARY_EXEC_PT_CONCEAL_VMX | SECONDARY_EXEC_USE_GPA_FOR_INTEL_PT | SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_ENABLE_VPID | SECONDARY_EXEC_UNRESTRICTED_GUEST);
  vmx_set_control_field(PIN_BASED_VM_EXEC_CONTROL, 0);
  vmx_set_control_field(VM_ENTRY_CONTROLS, VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_DEBUG_CONTROLS | VM_ENTRY_LOAD_IA32_EFER | VM_ENTRY_LOAD_IA32_LBR_CTL | VM_ENTRY_LOAD_IA32_RTIT_CTL | VM_ENTRY_PT_CONCEAL_PIP);
  vmx_set_control_field(VM_EXIT_CONTROLS, VM_EXIT_HOST_ADDR_SPACE_SIZE | VM_EXIT_SAVE_DEBUG_CONTROLS | VM_EXIT_SAVE_IA32_EFER | VM_EXIT_LOAD_IA32_EFER | VM_EXIT_CLEAR_IA32_LBR_CTL | VM_EXIT_CLEAR_IA32_RTIT_CTL | VM_EXIT_PT_CONCEAL_PIP);

  vmx_set_control_field(SECONDARY_VM_EXEC_CONTROL, SECONDARY_EXEC_ENABLE_INVPCID | SECONDARY_EXEC_ENABLE_RDTSCP | SECONDARY_EXEC_ENABLE_XSAVES_XSTORS);
  vmx_set_control_field(VM_ENTRY_CONTROLS, VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_DEBUG_CONTROLS | VM_ENTRY_LOAD_IA32_EFER);
  vmx_set_control_field(VM_EXIT_CONTROLS, VM_EXIT_HOST_ADDR_SPACE_SIZE | VM_EXIT_SAVE_DEBUG_CONTROLS | VM_EXIT_SAVE_IA32_EFER | VM_EXIT_LOAD_IA32_EFER);

  vmwrite(EPT_POINTER, vcpu->shared->ept_mgr.eptp.all);
  vmwrite(VIRTUAL_PROCESSOR_ID, VCPU_VPID);

  vmwrite(VMCS_LINK_POINTER, UINT64_MAX); // 禁用VMCS链接
  vmwrite(CR3_TARGET_COUNT, 0);
  vmwrite(TSC_OFFSET, 0);
  vmwrite(MSR_BITMAP, (uint64_t)vcpu->shared->msr_bitmap);
  vmwrite(EXCEPTION_BITMAP, 0);

  vmwrite(GUEST_CR0, read_cr0());
  vmwrite(GUEST_CR3, read_cr3());
  vmwrite(GUEST_CR4, read_cr4());
  vmwrite(CR0_READ_SHADOW, 0);
  vmwrite(CR4_READ_SHADOW, 0);
  vmwrite(CR0_GUEST_HOST_MASK, 0);
  vmwrite(CR4_GUEST_HOST_MASK, CR4_VMXE_MASK);

  vmwrite(GUEST_RSP, (uint64_t)vcpu->launch_rsp);
  vmwrite(GUEST_RIP, (uint64_t)vcpu->launch_rip);
  vmwrite(GUEST_RFLAGS, read_rflags());

  // 写入CS、DS、ES、SS、FS、GS、LDTR和TR寄存器的选择子和描述符信息
  vmwrite(GUEST_CS_SELECTOR, read_cs());
  vmwrite(GUEST_CS_BASE, 0);
  vmwrite(GUEST_CS_LIMIT, UINT64_MAX);
  vmwrite(GUEST_CS_AR_BYTES,
          vmx_convert_access_rights(read_cs_access_rights()));

  vmwrite(GUEST_DS_SELECTOR, read_ds());
  vmwrite(GUEST_DS_BASE, 0);
  vmwrite(GUEST_DS_LIMIT, UINT64_MAX);
  vmwrite(GUEST_DS_AR_BYTES,
          vmx_convert_access_rights(read_ds_access_rights()));

  vmwrite(GUEST_ES_SELECTOR, read_es());
  vmwrite(GUEST_ES_BASE, 0);
  vmwrite(GUEST_ES_LIMIT, UINT64_MAX);
  vmwrite(GUEST_ES_AR_BYTES,
          vmx_convert_access_rights(read_es_access_rights()));

  vmwrite(GUEST_SS_SELECTOR, read_ss());
  vmwrite(GUEST_SS_BASE, 0);
  vmwrite(GUEST_SS_LIMIT, UINT64_MAX);
  vmwrite(GUEST_SS_AR_BYTES,
          vmx_convert_access_rights(read_ss_access_rights()));

  vmwrite(GUEST_FS_SELECTOR, read_fs());
  vmwrite(GUEST_FS_BASE, 0);
  vmwrite(GUEST_FS_LIMIT, UINT64_MAX);
  vmwrite(GUEST_FS_AR_BYTES,
          vmx_convert_access_rights(read_fs_access_rights()));

  vmwrite(GUEST_GS_SELECTOR, read_gs());
  vmwrite(GUEST_GS_BASE, 0);
  vmwrite(GUEST_GS_LIMIT, UINT64_MAX);
  vmwrite(GUEST_GS_AR_BYTES,
          vmx_convert_access_rights(read_gs_access_rights()));

  vmwrite(GUEST_LDTR_SELECTOR, 0);
  vmwrite(GUEST_LDTR_BASE, 0);
  vmwrite(GUEST_LDTR_LIMIT, 0);
  vmwrite(GUEST_LDTR_AR_BYTES, vmx_convert_access_rights(0));

  vmwrite(GUEST_TR_SELECTOR, 0);
  vmwrite(GUEST_TR_BASE, 0);
  vmwrite(GUEST_TR_LIMIT, 0);
  vmwrite(GUEST_TR_AR_BYTES, vmx_convert_access_rights(0x8b00));

  gdtr_t gdtr;
  idtr_t idtr;
  read_gdtr((uint64_t)&gdtr);
  read_idtr((uint64_t)&idtr);
  vmwrite(GUEST_GDTR_BASE, gdtr.base);
  vmwrite(GUEST_GDTR_LIMIT, gdtr.limit);
  vmwrite(GUEST_IDTR_BASE, idtr.base);
  vmwrite(GUEST_IDTR_LIMIT, idtr.limit);

  vmwrite(HOST_CR0, read_cr0());
  vmwrite(HOST_CR3, (uint64_t)vcpu->shared->host_pt->pml4);
  vmwrite(HOST_CR4, read_cr4() | CR4_OSXSAVE_MASK); // 开启OSXSAVE，以处理guest xsetbv指令

  vmwrite(HOST_CS_SELECTOR, HOST_GDT_CS);
  vmwrite(HOST_DS_SELECTOR, 0);
  vmwrite(HOST_ES_SELECTOR, 0);
  vmwrite(HOST_SS_SELECTOR, 0);
  vmwrite(HOST_FS_SELECTOR, 0);
  vmwrite(HOST_GS_SELECTOR, 0);

  vmwrite(HOST_FS_BASE, 0);
  vmwrite(HOST_GS_BASE, 0);

  vmwrite(HOST_TR_SELECTOR, HOST_GDT_TR);

  vmwrite(HOST_TR_BASE, (uint64_t)vcpu->host_tss);

  vmwrite(HOST_GDTR_BASE, (uint64_t)vcpu->host_gdt);
  vmwrite(HOST_IDTR_BASE, UINT64_MAX);

  vmwrite(HOST_RSP, (uint64_t)&vcpu->host_stack->vcpu_pointer);
  vmwrite(HOST_RIP, (uint64_t)get_vm_exit_handler_asm());

  vmwrite(HOST_IA32_EFER, read_msr(MSR_IA32_EFER));
  vmwrite(HOST_IA32_SYSENTER_CS, read_msr(MSR_IA32_SYSENTER_CS));
  vmwrite(HOST_IA32_SYSENTER_ESP, read_msr(MSR_IA32_SYSENTER_ESP));
  vmwrite(HOST_IA32_SYSENTER_EIP, read_msr(MSR_IA32_SYSENTER_EIP));

  vmwrite(GUEST_DR7, read_dr7());
  vmwrite(GUEST_IA32_DEBUGCTL, read_msr(MSR_IA32_DEBUGCTL));
  vmwrite(GUEST_IA32_EFER, read_msr(MSR_IA32_EFER));
  vmwrite(GUEST_SYSENTER_CS, read_msr(MSR_IA32_SYSENTER_CS));
  vmwrite(GUEST_SYSENTER_ESP, read_msr(MSR_IA32_SYSENTER_ESP));
  vmwrite(GUEST_SYSENTER_EIP, read_msr(MSR_IA32_SYSENTER_EIP));
}

void launch_vcpu_asm(vcpu_t *vcpu);

int launch_vcpu(vcpu_t *vcpu)
{
  uint64_t vmx_basic = read_msr(MSR_IA32_VMX_BASIC);

  if (!vmx_check_cpuid())
  {
    PRINTF("CPU does not support Intel virtualization features\n");
    return -1;
  }
  if (!vmx_check_feature_control())
  {
    PRINTF(
        "CPU virtualization is locked\n");
    return -1;
  }
  if (!(vmx_basic & VMX_BASIC_TRUE_CONTROLS))
  {
    PRINTF("CPU does not support VMX true controls\n");
    return -1;
  }

  zero_mem(vcpu->vmxon_region, sizeof(vmxon_t));
  zero_mem(vcpu->vmcs_region, sizeof(vmcs_t));
  vcpu->vmxon_region->revision_id = vmx_basic & VMX_BASIC_REVISION_MASK;
  vcpu->vmcs_region->revision_id = vmx_basic & VMX_BASIC_REVISION_MASK;

  uint64_t cr0 = read_cr0();
  uint64_t cr4 = read_cr4();
  cr0 = vmx_ajust_cr0(cr0);
  cr4 = vmx_ajust_cr4(cr4);
  write_cr0(cr0);
  write_cr4(cr4);

  uint64_t addr = (uint64_t)(vcpu->vmxon_region);
  if (vmxon(&addr) != 0)
  {
    PRINTF("Failed to enter VMX operation mode\n");
    return -1;
  }
  addr = (uint64_t)(vcpu->vmcs_region);
  if (vmclear(&addr) != 0)
  {
    vmxoff();
    PRINTF("Failed to clear VMCS\n");
    return -1;
  }
  addr = (uint64_t)(vcpu->vmcs_region);
  if (vmptrld(&addr) != 0)
  {
    vmxoff();
    PRINTF("Failed to load VMCS\n");
    return -1;
  }
  setup_vmcs(vcpu);
  // invvpid_single(VCPU_VPID);
  // invept_single(vcpu->shared->ept_mgr.eptp.all);
  launch_vcpu_asm(vcpu);
  PRINTF("Failed to launch VCPU: %x\n", vmread(VM_INSTRUCTION_ERROR));
  return -1;
}

void dump_regs(regs_t *regs)
{
  PRINTF("RAX: 0x%x\n", regs->rax);
  PRINTF("RCX: 0x%x\n", regs->rcx);
  PRINTF("RDX: 0x%x\n", regs->rdx);
  PRINTF("RBX: 0x%x\n", regs->rbx);
  PRINTF("RBP: 0x%x\n", regs->rbp);
  PRINTF("RSI: 0x%x\n", regs->rsi);
  PRINTF("RDI: 0x%x\n", regs->rdi);
  PRINTF("R8: 0x%x\n", regs->r8);
  PRINTF("R9: 0x%x\n", regs->r9);
  PRINTF("R10: 0x%x\n", regs->r10);
  PRINTF("R11: 0x%x\n", regs->r11);
  PRINTF("R12: 0x%x\n", regs->r12);
  PRINTF("R13: 0x%x\n", regs->r13);
  PRINTF("R14: 0x%x\n", regs->r14);
  PRINTF("R15: 0x%x\n\n", regs->r15);
}

static uint64_t get_xcr_supported_bits()
{
  uint64_t rax = 0xd, rcx = 0, rdx = 0, rbx = 0;
  cpuid_wrapper(&rax, &rcx, &rdx, &rbx);
  return (rax & 0xffffffff) | (rdx << 32);
}

static uint64_t get_extended_model_id()
{
  uint64_t rax = 0x1, rcx = 0, rdx, rbx;
  cpuid_wrapper(&rax, &rcx, &rdx, &rbx);
  return (rax >> 16) & 0xf;
}

static int is_valid_msr(uint32_t index)
{
  if ((index <= MSR_ID_LOW_MAX) ||
      (index >= MSR_ID_HIGH_MIN && index <= MSR_ID_HIGH_MAX))
  {
    return 1;
  }
  else
  {
    return 0;
  }
}

void handle_rdmsr(regs_t *regs)
{
  if (!is_valid_msr(regs->rcx))
  {
    PRINTF("Invalid MSR access: %x\n", regs->rcx);
    vmx_inject_gp(0);
    return;
  }
  uint64_t value = read_msr(regs->rcx);
  if (regs->rcx == MSR_IA32_FEATURE_CONTROL)
  {
    ia32_feature_control_register_t feature_control = {0};
    feature_control.all = value;
    feature_control.lock_bit = 1;
    feature_control.enable_vmx_outside_smx = 0;
    value = feature_control.all;
  }
  regs->rax = value >> 32;
  regs->rdx = value & 0xffffffff;
  vmx_advance_rip();
}

void handle_wrmsr(regs_t *regs)
{
  if (!is_valid_msr(regs->rcx))
  {
    PRINTF("Invalid MSR access: %x\n", regs->rcx);
    vmx_inject_gp(0);
    return;
  }
  uint64_t value = regs->rax << 32 | regs->rdx;
  write_msr(regs->rcx, value);
  vmx_advance_rip();
}

int is_valid_xcr(uint64_t xcr)
{
  uint64_t xcr_supported_bits = get_xcr_supported_bits();

  if (xcr & ~xcr_supported_bits)
  {
    return 0;
  }

  if (!(xcr & XFEATURE_MASK_FP))
  {
    return 0;
  }
  if ((xcr & XFEATURE_MASK_YMM) && !(xcr & XFEATURE_MASK_SSE))
  {
    return 0;
  }
  if ((!(xcr & XFEATURE_MASK_BNDREGS)) !=
      (!(xcr & XFEATURE_MASK_BNDCSR)))
  {
    return 0;
  }
  if (xcr & XFEATURE_MASK_AVX512)
  {
    if (!(xcr & XFEATURE_MASK_YMM))
      return 0;
    if ((xcr & XFEATURE_MASK_AVX512) != XFEATURE_MASK_AVX512)
      return 0;
  }

  if ((xcr & XFEATURE_MASK_XTILE) &&
      ((xcr & XFEATURE_MASK_XTILE) != XFEATURE_MASK_XTILE))
    return 0;
  return 1;
}

void handle_xsetbv(regs_t *regs)
{
  uint32_t index = regs->rcx;
  uint64_t xcr = (regs->rax & 0xffffffff) | regs->rdx << 32;
  if (index != 0)
  {
    vmx_inject_gp(0);
    return;
  }
  if (!is_valid_xcr(xcr))
  {
    vmx_inject_gp(0);
    return;
  }
  xsetbv(index, xcr);
  vmx_advance_rip();
}

void handle_init(regs_t *regs)
{
  uint64_t extended_model_id = get_extended_model_id();
  regs->rax = 0;
  regs->rcx = 0;
  regs->rdx = 0;
  regs->rbx = 0x600 | (extended_model_id << 16);
  regs->rbp = 0;
  regs->rsi = 0;
  regs->rdi = 0;
  regs->r8 = 0;
  regs->r9 = 0;
  regs->r10 = 0;
  regs->r11 = 0;
  regs->r12 = 0;
  regs->r13 = 0;
  regs->r14 = 0;
  regs->r15 = 0;

  write_cr2(0);
  write_dr0(0);
  write_dr1(0);
  write_dr2(0);
  write_dr3(0);
  write_dr6(0xffff0ff0);

  uint64_t cr0 = vmread(GUEST_CR0);
  cr0 &= CR0_CD_MASK | CR0_NW_MASK;
  cr0 |= CR0_ET_MASK;
  cr0 = vmx_ajust_cr0(cr0);
  cr0 &= ~CR0_PE_MASK;
  cr0 &= ~CR0_PG_MASK;
  vmwrite(GUEST_CR0, cr0);
  vmwrite(CR0_READ_SHADOW, cr0);

  uint64_t cr4 = vmx_ajust_cr4(0);
  vmwrite(GUEST_CR4, cr4);
  vmwrite(CR4_READ_SHADOW, cr4 & ~CR4_VMXE_MASK);

  vmwrite(GUEST_CR3, 0);
  vmwrite(GUEST_DR7, 0x400);
  vmwrite(GUEST_IA32_EFER, 0);

  vmx_segment_ar_t code_ar = {0}, data_ar = {0}, ldtr_ar = {0}, task_ar = {0};

  code_ar.present = data_ar.present = ldtr_ar.present = task_ar.present = 1;
  code_ar.descriptor_type = data_ar.descriptor_type = 1;

  code_ar.segment_type = SEGMENT_CODE_RX_ACCESSED;
  data_ar.segment_type = SEGMENT_DATA_RW_ACCESSED;
  ldtr_ar.segment_type = SEGMENT_SYSTEM_LDT;
  task_ar.segment_type = SEGMENT_SYSTEM_32BIT_TSS_BUSY;

  vmwrite(GUEST_CS_SELECTOR, 0xf000);
  vmwrite(GUEST_CS_BASE, 0xffff0000);
  vmwrite(GUEST_CS_LIMIT, 0xffff);
  vmwrite(GUEST_CS_AR_BYTES, code_ar.all);
  vmwrite(GUEST_SS_SELECTOR, 0);
  vmwrite(GUEST_SS_BASE, 0);
  vmwrite(GUEST_SS_LIMIT, 0xffff);
  vmwrite(GUEST_SS_AR_BYTES, data_ar.all);
  vmwrite(GUEST_DS_SELECTOR, 0);
  vmwrite(GUEST_DS_BASE, 0);
  vmwrite(GUEST_DS_LIMIT, 0xffff);
  vmwrite(GUEST_DS_AR_BYTES, data_ar.all);
  vmwrite(GUEST_ES_SELECTOR, 0);
  vmwrite(GUEST_ES_BASE, 0);
  vmwrite(GUEST_ES_LIMIT, 0xffff);
  vmwrite(GUEST_ES_AR_BYTES, data_ar.all);
  vmwrite(GUEST_FS_SELECTOR, 0);
  vmwrite(GUEST_FS_BASE, 0);
  vmwrite(GUEST_FS_LIMIT, 0xffff);
  vmwrite(GUEST_FS_AR_BYTES, data_ar.all);
  vmwrite(GUEST_GS_SELECTOR, 0);
  vmwrite(GUEST_GS_BASE, 0);
  vmwrite(GUEST_GS_LIMIT, 0xffff);
  vmwrite(GUEST_GS_AR_BYTES, data_ar.all);
  vmwrite(GUEST_TR_SELECTOR, 0);
  vmwrite(GUEST_TR_BASE, 0);
  vmwrite(GUEST_TR_LIMIT, 0xffff);
  vmwrite(GUEST_TR_AR_BYTES, task_ar.all);
  vmwrite(GUEST_LDTR_SELECTOR, 0);
  vmwrite(GUEST_LDTR_BASE, 0);
  vmwrite(GUEST_LDTR_LIMIT, 0xffff);
  vmwrite(GUEST_LDTR_AR_BYTES, ldtr_ar.all);

  vmwrite(GUEST_GDTR_BASE, 0);
  vmwrite(GUEST_GDTR_LIMIT, 0xffff);
  vmwrite(GUEST_IDTR_BASE, 0);
  vmwrite(GUEST_IDTR_LIMIT, 0xffff);

  vmwrite(GUEST_RFLAGS, 2);
  vmwrite(GUEST_RIP, 0xfff0);
  vmwrite(GUEST_RSP, 0);

  vmx_guest_exit_ia32e(); // 退出IA32E

  invvpid_single(vmread(VIRTUAL_PROCESSOR_ID));

  vmwrite(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_WAIT_SIPI);
}

void handle_sipi()
{
  uint64_t vector = vmread(EXIT_QUALIFICATION);
  vmwrite(GUEST_CS_SELECTOR, vector << 8);
  vmwrite(GUEST_CS_BASE, vector << 12);
  vmwrite(GUEST_RIP, 0);
  vmwrite(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
}

void vm_exit_handler(vcpu_t *vcpu)
{
  regs_t *regs = &(vcpu->guest_regs);
  uint64_t exit_reason = vmread(VM_EXIT_REASON);
  // PRINTF("VM_EXIT_REASON: 0x%x\n", exit_reason);
  switch (exit_reason)
  {
  case EXIT_REASON_CPUID:
    cpuid_wrapper(&regs->rax, &regs->rcx,
                  &regs->rdx, &regs->rbx);
    vmx_advance_rip();
    break;
  case EXIT_REASON_XSETBV:
    VCPU_PRINTF(vcpu, "VM EXIT: XSETBV\n");
    handle_xsetbv(regs);
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
    vmx_inject_ud();
    break;
  case EXIT_REASON_MSR_READ:
    VCPU_PRINTF(vcpu, "VM EXIT: MSR_READ\n");
    handle_rdmsr(regs);
    break;
  case EXIT_REASON_MSR_WRITE:
    VCPU_PRINTF(vcpu, "VM EXIT: MSR_WRITE\n");
    handle_wrmsr(regs);
    break;
  case EXIT_REASON_INIT:
    VCPU_PRINTF(vcpu, "VM EXIT: INIT\n");
    handle_init(regs);
    break;
  case EXIT_REASON_SIPI:
    VCPU_PRINTF(vcpu, "VM EXIT: SIPI\n");
    handle_sipi();
    break;
  default:
    VCPU_PRINTF(vcpu, "Unhandled VM EXIT: 0x%x\n", exit_reason);
    goto err;
    break;
  }
  return;
err:
  PRINTF("Failed to handle VM EXIT\n");
  PANIC();
}

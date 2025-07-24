#include "vcpu.h"
#include "basic_lib.h"
#include "intrin.h"
#include "run.h"

#define HOST_GDT_CS 0x08
#define HOST_GDT_TR 0x10

#define VCPU_VPID 1

// 打印时带上VCPU编号
#define VCPU_PRINTF(vcpu, fmt, ...) PRINTF("VCPU%d: " fmt, vcpu->vcpu_id, ##__VA_ARGS__)

// 检查CPU是否支持1G大页
static int check_pdpe1gb()
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

static void build_identity_pdpt(pdpt_entry_t *pdpt)
{
  zero_mem(pdpt, PAGE_SIZE);
  for (int i = 0; i < 512; i++)
  {
    uint64_t phys_base = (uint64_t)i * 0x40000000; // 1G对齐地址

    pdpt[i] = (pdpt_entry_t){
        .present = 1,
        .write = 1,
        .user = 0, // 仅内核可访问
        .pwt = 0,  // 未使用
        .pcd = 0,  // 未使用
        .reserved1 = 0,
        .page_size = 1, // 启用1G大页[4,6](@ref)
        .reserved2 = 0,
        .pfn = phys_base >> 12, // 物理基址高40位
        .nx = 0                 // 允许执行
    };
  }
}

static void set_pml4_entry(pml4_entry_t *entry, pdpt_entry_t *pdpt)
{
  *entry = (pml4_entry_t){
      .present = 1,                // 页表项有效
      .write = 1,                  // 允许读写
      .user = 0,                   // 仅内核态可访问
      .pwt = 0,                    // Write-Back缓存策略
      .pcd = 0,                    // 启用缓存
      .accessed = 0,               // 初始未访问
      .reserved1 = 0,              // 硬件保留位（必须置0）[8]
      .ignored = 0,                // 位8-11（系统保留，置0）
      .pfn = (uint64_t)pdpt >> 12, // PDPT物理地址高40位
      .available = 0,              // 系统软件保留位
      .nx = 0                      // 允许代码执行
  };
}

int init_vcpu_shared(vcpu_shared_t *vcpu_shared)
{
  if (!check_pdpe1gb())
  {
    PRINTF("CPU does not support pdpe1gb feature.\n");
    return -1;
  }
  init_msr_bitmap(vcpu_shared->msr_bitmap);
  msr_bitmap_set_read(vcpu_shared->msr_bitmap, MSR_IA32_FEATURE_CONTROL);

  build_identity_pdpt(vcpu_shared->host_pt->identity_pdpt);
  zero_mem(vcpu_shared->host_pt->pml4, PAGE_SIZE);
  set_pml4_entry(vcpu_shared->host_pt->pml4, vcpu_shared->host_pt->identity_pdpt);

  init_ept(&vcpu_shared->ept_mgr);

  vcpu_shared->vcpu_num = 0;

  return 0;
}

static void setup_task_desc(gdt_desc128_t *desc, uint64_t tss_base)
{
  desc->limit_low = 103;
  desc->base_low = tss_base & 0xFFFF;
  desc->base_mid = (tss_base >> 16) & 0xFF;
  desc->base_high = (tss_base >> 24) & 0xFF;
  desc->base_upper32 = (tss_base >> 32) & 0xFFFFFFFF;
  desc->type = 0x9;
  desc->s = 0;
  desc->dpl = 0;
  desc->p = 1;
  desc->limit_high = 0;
  desc->avl = 0;
  desc->l = 0;
  desc->db = 0;
  desc->g = 0;
  desc->reserved = 0;
}

// 构造x86_64代码段描述符
static void setup_code_desc(gdt_desc_t *desc)
{
  desc->limit_low = 0xFFFF;
  desc->base_low = 0;
  desc->base_mid = 0;
  desc->type = 0xA; // 可执行，非一致，向上扩展
  desc->s = 1;
  desc->dpl = 0;
  desc->p = 1;
  desc->limit_high = 0xF;
  desc->avl = 0;
  desc->l = 1;
  desc->db = 0;
  desc->g = 1;
  desc->base_high = 0;
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
  zero_mem(vcpu->host_tss, sizeof(host_tss_t));
  zero_mem(vcpu->host_gdt, sizeof(host_gdt_t));
  setup_code_desc(&vcpu->host_gdt->code);
  setup_task_desc(&vcpu->host_gdt->task, (uint64_t)(vcpu->host_tss));
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

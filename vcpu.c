#include "vcpu.h"
#include "basic_lib.h"
#include "intrin.h"

void *vcpu_alloc_mem(vcpu_t *vcpu, uintptr_t size, uintptr_t alignment)
{
  return mem_pool_alloc(vcpu->mem_pool, size, alignment);
}

static void setup_tss_desc(gdt_desc128_t *desc, uint64_t tss_base)
{
  desc->limit_low = TSS_SIZE - 1;
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

int vcpu_setup_host_stack(vcpu_t *vcpu)
{
  vcpu->host_stack = vcpu_alloc_aligned_mem(vcpu, HOST_STACK_SIZE);
  vcpu->host_rsp = (uint64_t)vcpu->host_stack + HOST_STACK_SIZE - 16;
  if (vcpu->host_stack == NULL)
  {
    return -1;
  }
  return 0;
}

int vcpu_setup_host_gdt(vcpu_t *vcpu)
{
  vcpu->host_gdt = vcpu_alloc_aligned_mem(vcpu, HOST_GDT_SIZE);
  if (vcpu->host_gdt == NULL)
  {
    return -1;
  }
  vcpu->host_tss = vcpu_alloc_aligned_mem(vcpu, TSS_SIZE);
  if (vcpu->host_tss == NULL)
  {
    return -1;
  }
  zero_mem(vcpu->host_tss, TSS_SIZE);
  zero_mem(vcpu->host_gdt, HOST_GDT_SIZE);
  setup_code_desc(
      (gdt_desc_t *)((uintptr_t)(vcpu->host_gdt) + (HOST_GDT_CS & 0xfff8)));
  setup_tss_desc(
      (gdt_desc128_t *)((uintptr_t)(vcpu->host_gdt) + (HOST_GDT_TR & 0xfff8)),
      (uint64_t)(vcpu->host_tss));
  return 0;
}

// 检查CPU是否支持1G大页
static int check_cpu_big_page_feature()
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

static void setup_identity_pdpt(pdpt_entry_t *pdpt)
{
  zero_mem(pdpt, PAGE_TABLE_SIZE * sizeof(pdpt_entry_t));
  for (int i = 0; i < PAGE_TABLE_SIZE; i++)
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

int vcpu_setup_host_identity_pml4(vcpu_t *vcpu)
{

  vcpu->host_pml4 =
      vcpu_alloc_page(vcpu);
  if (vcpu->host_pml4 == NULL)
  {
    return -1;
  }
  pdpt_entry_t *identity_pdpt =
      vcpu_alloc_page(vcpu);
  if (identity_pdpt == NULL)
  {
    return -1;
  }

  zero_mem(identity_pdpt, PAGE_TABLE_SIZE * sizeof(pdpt_entry_t));
  zero_mem(vcpu->host_pml4, PAGE_TABLE_SIZE * sizeof(pml4_entry_t));
  vcpu->host_pml4[0] = (pml4_entry_t){
      .present = 1,                         // 页表项有效
      .write = 1,                           // 允许读写
      .user = 0,                            // 仅内核态可访问
      .pwt = 0,                             // Write-Back缓存策略
      .pcd = 0,                             // 启用缓存
      .accessed = 0,                        // 初始未访问
      .reserved1 = 0,                       // 硬件保留位（必须置0）[8]
      .ignored = 0,                         // 位8-11（系统保留，置0）
      .pfn = (uint64_t)identity_pdpt >> 12, // PDPT物理地址高40位
      .available = 0,                       // 系统软件保留位
      .nx = 0                               // 允许代码执行
  };

  setup_identity_pdpt(identity_pdpt);

  return 0;
}

vcpu_t *vcpu_create(mem_pool_t *mem_pool)
{

  vcpu_t *vcpu = mem_pool_alloc(mem_pool, sizeof(vcpu_t), 16);

  if (vcpu == NULL)
  {
    PRINT_INFO("Failed to allocate VCPU structure\n");
    return NULL;
  }
  vcpu->mem_pool = mem_pool;

  return vcpu;
}

int vcpu_init(vcpu_t *vcpu)
{
  if (!check_cpu_big_page_feature())
  {
    PRINT_INFO("CPU does not support 1GB pages\n");
    return -1;
  }
  if (vcpu_setup_host_stack(vcpu) != 0)
  {
    PRINT_INFO("Failed to setup host stack\n");
    return -1;
  }

  if (vcpu_setup_host_gdt(vcpu) != 0)
  {
    PRINT_INFO("Failed to setup host GDT\n");
    return -1;
  }

  if (vcpu_setup_host_identity_pml4(vcpu) != 0)
  {
    PRINT_INFO("Failed to setup host identity PML4\n");
    return -1;
  }
  return 0;
}

void vcpu_dump_regs(vcpu_t *vcpu)
{
  PRINT_DEBUG("GUEST REGISTERS DUMP\n");
  PRINT_DEBUG("RIP: 0x%x\n", vcpu->regs.rip);
  PRINT_DEBUG("RSP: 0x%x\n", vcpu->regs.rsp);
  PRINT_DEBUG("RAX: 0x%x\n", vcpu->regs.rax);
  PRINT_DEBUG("RCX: 0x%x\n", vcpu->regs.rcx);
  PRINT_DEBUG("RDX: 0x%x\n", vcpu->regs.rdx);
  PRINT_DEBUG("RBX: 0x%x\n", vcpu->regs.rbx);
  PRINT_DEBUG("RBP: 0x%x\n", vcpu->regs.rbp);
  PRINT_DEBUG("RSI: 0x%x\n", vcpu->regs.rsi);
  PRINT_DEBUG("RDI: 0x%x\n", vcpu->regs.rdi);
  PRINT_DEBUG("R8: 0x%x\n", vcpu->regs.r8);
  PRINT_DEBUG("R9: 0x%x\n", vcpu->regs.r9);
  PRINT_DEBUG("R10: 0x%x\n", vcpu->regs.r10);
  PRINT_DEBUG("R11: 0x%x\n", vcpu->regs.r11);
  PRINT_DEBUG("R12: 0x%x\n", vcpu->regs.r12);
  PRINT_DEBUG("R13: 0x%x\n", vcpu->regs.r13);
  PRINT_DEBUG("R14: 0x%x\n", vcpu->regs.r14);
  PRINT_DEBUG("R15: 0x%x\n\n", vcpu->regs.r15);
}

void vcpu_host_push(vcpu_t *vcpu, uint64_t value)
{
  vcpu->host_rsp -= sizeof(value);
  *(uint64_t *)vcpu->host_rsp = value;
}

void vcpu_emulate_cpuid(vcpu_t *vcpu, int instruction_len)
{
  cpuid_wrapper(&vcpu->regs.rax, &vcpu->regs.rcx,
                &vcpu->regs.rdx, &vcpu->regs.rbx);
  vcpu->regs.rip += instruction_len;
}

void vcpu_emulate_invd(vcpu_t *vcpu, int instruction_len)
{
  wbinvd_wrapper();
  vcpu->regs.rip += instruction_len;
}

static void enable_os_xsave()
{
  uint64_t cr4 = read_cr4();
  cr4 |= CR4_OSXSAVE_MASK;
  write_cr4(cr4);
}

void vcpu_emulate_xsetbv(vcpu_t *vcpu, int instruction_len)
{
  enable_os_xsave();
  xsetbv_wrapper(vcpu->regs.rcx, vcpu->regs.rax, vcpu->regs.rdx);
  vcpu->regs.rip += instruction_len;
}

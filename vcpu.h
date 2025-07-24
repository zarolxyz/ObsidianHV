#pragma once

#include <stdint.h>
#include "ia32.h"
#include "basic_lib.h"
#include "vmx.h"
#include "ept.h"
#include "run.h"

#pragma pack(push, 1)

typedef struct
{
  uint16_t limit_low;
  uint16_t base_low;
  uint8_t base_mid;
  uint8_t type : 4;
  uint8_t s : 1;
  uint8_t dpl : 2;
  uint8_t p : 1;
  uint8_t limit_high : 4;
  uint8_t avl : 1;
  uint8_t l : 1;
  uint8_t db : 1;
  uint8_t g : 1;
  uint8_t base_high;
} gdt_desc_t;

typedef struct
{
  uint16_t limit_low;
  uint16_t base_low;
  uint8_t base_mid;
  uint8_t type : 4;
  uint8_t s : 1;
  uint8_t dpl : 2;
  uint8_t p : 1;
  uint8_t limit_high : 4;
  uint8_t avl : 1;
  uint8_t l : 1;
  uint8_t db : 1;
  uint8_t g : 1;
  uint8_t base_high;
  uint32_t base_upper32;
  uint32_t reserved;
} gdt_desc128_t;

typedef struct
{
  uint16_t limit; // 限长
  uint64_t base;  // 基址
} gdtr_t, idtr_t;

typedef struct
{
  uint64_t present : 1;
  uint64_t write : 1;
  uint64_t user : 1;
  uint64_t pwt : 1;
  uint64_t pcd : 1;
  uint64_t accessed : 1;
  uint64_t reserved1 : 2;
  uint64_t ignored : 4;
  uint64_t pfn : 40;
  uint64_t available : 11;
  uint64_t nx : 1;
} pml4_entry_t;

typedef struct
{
  uint64_t present : 1;
  uint64_t write : 1;
  uint64_t user : 1;
  uint64_t pwt : 1;
  uint64_t pcd : 1;
  uint64_t reserved1 : 2;
  uint64_t page_size : 1;
  uint64_t reserved2 : 4;
  uint64_t pfn : 40;
  uint64_t available : 11;
  uint64_t nx : 1;
} pdpt_entry_t;

#pragma pack(pop)

typedef struct
{
  uint8_t data[8192 - sizeof(uint64_t)];
  uint64_t vcpu_pointer;
} host_stack_t;

typedef struct
{
  gdt_desc_t null;
  gdt_desc_t code;
  gdt_desc128_t task;
} host_gdt_t;

typedef struct
{
  uint8_t data[104];
} host_tss_t;

typedef struct
{
  pml4_entry_t pml4[512];
  pdpt_entry_t identity_pdpt[512];
} host_pt_t;

typedef struct
{
  host_pt_t *host_pt; // HOST的页表
  msr_bitmap_t *msr_bitmap;
  ept_mgr_t ept_mgr;
  int vcpu_num;
} vcpu_shared_t;
typedef struct
{
  regs_t guest_regs;   // 每次vmexit时，保存guest的寄存器
  uint64_t launch_rip; // 第一次进入vmx非根模式时，rip指向这里
  uint64_t launch_rsp; // 第一次进入vmx非根模式时，rsp指向这里
  host_stack_t *host_stack;
  host_gdt_t *host_gdt;
  host_tss_t *host_tss;
  vcpu_shared_t *shared;
  vmxon_t *vmxon_region;
  vmcs_t *vmcs_region;
  int vcpu_id;
} vcpu_t;

int init_vcpu_shared(vcpu_shared_t *vcpu_shared);
void init_vcpu(vcpu_t *vcpu, vcpu_shared_t *shared);
int capture_guest_regs(vcpu_t *vcpu);
int launch_vcpu(vcpu_t *vcpu);
void dump_host_state(void);
void dump_guest_state(void);

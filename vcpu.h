#pragma once

#include <stdint.h>
#include "intrin.h"
#include "basic_lib.h"
#include "vmx.h"
#include "ept.h"
#include "hvos.h"

#pragma pack(push, 1)

typedef struct
{
  uint8_t data[8192 - sizeof(uint64_t)];
  uint64_t vcpu_pointer;
} host_stack_t;

typedef struct
{
  uint64_t rax;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rbx;
  uint64_t rbp;
  uint64_t rsi;
  uint64_t rdi;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
} regs_t;

#pragma pack(pop)

typedef struct
{
  hvos_shared_t hv_shared;
  msr_bitmap_t *msr_bitmap;
  ept_mgr_t ept_mgr;
} vcpu_shared_t;
typedef struct
{
  regs_t guest_regs;   // 每次vmexit时，保存guest的寄存器
  uint64_t launch_rip; // 第一次进入vmx非根模式时，rip指向这里
  uint64_t launch_rsp; // 第一次进入vmx非根模式时，rsp指向这里
  host_stack_t *host_stack;
  hvos_cpu_t hv_cpu;
  vcpu_shared_t *shared;
  vmxon_t *vmxon_region;
  vmcs_t *vmcs_region;
} vcpu_t;

int init_vcpu_shared(vcpu_shared_t *vcpu_shared);
void init_vcpu(vcpu_t *vcpu, vcpu_shared_t *shared);
int capture_guest_regs(vcpu_t *vcpu);
int launch_vcpu(vcpu_t *vcpu);
void dump_host_state(void);
void dump_guest_state(void);

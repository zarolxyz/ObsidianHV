#pragma once

#include <stdint.h>
#include "ia32.h"
#include "basic_lib.h"

#define HOST_STACK_SIZE 8192

#define HOST_GDT_CS 0x08
#define HOST_GDT_TR 0x10
#define HOST_GDT_SIZE 0x20

#define TSS_SIZE 104
#define TSS_AR 0x8b00

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
  uint64_t rip;
  uint64_t rsp;
} regs_t;

typedef struct
{
  regs_t regs;
  void *host_stack;
  uint64_t host_rsp;
  pml4_entry_t *host_pml4;
  gdt_desc_t *host_gdt;
  void *host_tss;
  mem_pool_t *mem_pool;
} vcpu_t;

void *vcpu_alloc_mem(vcpu_t *vcpu, uintptr_t size, uintptr_t alignment);
static inline void *vcpu_alloc_aligned_mem(vcpu_t *vcpu, uintptr_t size)
{
  return vcpu_alloc_mem(vcpu, size, 16);
}
static inline void *vcpu_alloc_page(vcpu_t *vcpu)
{
  return vcpu_alloc_mem(vcpu, PAGE_SIZE, PAGE_SIZE);
}
int vcpu_init(vcpu_t *vcpu);
void vcpu_capture_entry(vcpu_t *vcpu);
vcpu_t *vcpu_create(mem_pool_t *mem_pool);
void vcpu_dump_regs(vcpu_t *vcpu);
void vcpu_host_push(vcpu_t *vcpu, uint64_t value);
void vcpu_emulate_cpuid(regs_t *regs);
void vcpu_emulate_invd(regs_t *regs);
void vcpu_emulate_xsetbv(regs_t *regs);
void vcpu_emulate_init(regs_t *regs);

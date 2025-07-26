#pragma once

// 此模块构建基本的操作系统数据结构，以支持宿主运行

#include "intrin.h"

// 打印时带上CPU编号
#define CPU_PRINTF(hv_cpu, fmt, ...) PRINTF("CPU%d: " fmt, (hv_cpu)->cpu_id, ##__VA_ARGS__)

#define HV_CS 0x08
#define HV_TR 0x10

#pragma pack(push, 1)

typedef struct
{
    segment_desc_t null;
    segment_desc_t code;
    segment_desc64_t task;
} hvos_gdt_t;

typedef struct
{
    gate_desc_t gates[256];
} hvos_idt_t;

typedef struct
{
    pml4e_t pml4[512];
    pdpte_t pdpt[512];
} hvos_pt_t;

#pragma pack(pop)

typedef struct
{
    hvos_pt_t *pt;
    hvos_idt_t *idt;
    int cpu_num;
} hvos_shared_t;

typedef struct
{
    hvos_gdt_t *gdt;
    tss_t *tss;
    int cpu_id;
    hvos_shared_t *shared;
} hvos_cpu_t;

int init_hvos_shared_data(hvos_shared_t *shared);
void init_hvos_cpu(hvos_cpu_t *cpu, hvos_shared_t *shared);

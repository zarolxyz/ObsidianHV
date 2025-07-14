#pragma once

#include <stdint.h>

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

#define PAGE_TABLE_SIZE 512

typedef struct
{
  // 权限与状态标志
  uint64_t present : 1;   // 位0: 页是否有效
  uint64_t write : 1;     // 位1: 可写权限 (1=可写)
  uint64_t user : 1;      // 位2: 访问权限 (1=用户态可访问)
  uint64_t pwt : 1;       // 位3: 写缓存策略 (1=Write-Through)
  uint64_t pcd : 1;       // 位4: 缓存禁用 (1=禁用缓存)
  uint64_t accessed : 1;  // 位5: 访问标记 (CPU自动置位)
  uint64_t reserved1 : 2; // 位6-7: 必须为0 (硬件保留)
  uint64_t ignored : 4;   // 位8-11: 忽略（可保留或供OS使用）

  // 物理地址与控制位
  uint64_t pfn : 40;       // 位12-51: 下一级页表物理地址高40位
  uint64_t available : 11; // 位52-62: 供操作系统自由使用
  uint64_t nx : 1;         // 位63: 禁止执行位 (1=禁止执行)
} pml4_entry_t;

typedef struct
{
  uint64_t present : 1;    // 位0
  uint64_t write : 1;      // 位1
  uint64_t user : 1;       // 位2
  uint64_t pwt : 1;        // 位3 (Page Write-Through)
  uint64_t pcd : 1;        // 位4 (Page Cache Disable)
  uint64_t reserved1 : 2;  // 位5-6 (必须为0)
  uint64_t page_size : 1;  // 位7
  uint64_t reserved2 : 4;  // 位8-11 (必须为0)
  uint64_t pfn : 40;       // 位12-51
  uint64_t available : 11; // 位52-62
  uint64_t nx : 1;         // 位63
} pdpt_entry_t;

#define HIGH_MSR_BASE 0xc0000000

static inline int is_high_msr(uint32_t index) { return index >= HIGH_MSR_BASE; }

static inline int is_valid_msr(uint32_t index)
{
  // Check if the MSR index is within the valid range (0x00000000 to 0xFFFFFFFF)
  // Typically, MSRs are in the range 0x00000000 to 0x00001FFF and 0xC0000000 to
  // 0xC0001FFF
  if ((index <= 0x00001FFF) ||
      (index >= HIGH_MSR_BASE && index <= HIGH_MSR_BASE + 0x00001FFF))
  {
    return 1; // Valid MSR index
  }
  else
  {
    return 0; // Invalid MSR index
  }
}

// CR4 基础功能标志位 (常用)
#define CR4_VME_MASK (1UL << 0)         // 虚拟8086模式扩展（Virtual-8086 Mode Extensions）[6,7](@ref)
#define CR4_PVI_MASK (1UL << 1)         // 保护模式虚拟中断（Protected-Mode Virtual Interrupts）[6](@ref)
#define CR4_TSD_MASK (1UL << 2)         // 时间戳计数器特权级限制（Time Stamp Disable）[6,8](@ref)
#define CR4_DE_MASK (1UL << 3)          // 调试扩展（Debugging Extensions）[6,7](@ref)
#define CR4_PSE_MASK (1UL << 4)         // 页大小扩展（Page Size Extensions），启用4MB大页[4,7](@ref)
#define CR4_PAE_MASK (1UL << 5)         // 物理地址扩展（Physical Address Extension），启用36+位物理地址[4,7](@ref)
#define CR4_MCE_MASK (1UL << 6)         // 机器检查异常（Machine Check Exception）[6,8](@ref)
#define CR4_PGE_MASK (1UL << 7)         // 全局页使能（Page Global Enable）[6,7](@ref)
#define CR4_PCE_MASK (1UL << 8)         // 性能监控计数器特权级（Performance Monitoring Counter Enable）[6](@ref)
#define CR4_OSFXSR_MASK (1UL << 9)      // SSE指令支持（OS Support for FXSAVE/FXRSTOR）[6,8](@ref)
#define CR4_OSXMMEXCPT_MASK (1UL << 10) // SIMD浮点异常支持（OS Support for Unmasked SIMD FP Exceptions）[6](@ref)
#define CR4_UMIP_MASK (1UL << 11)       // 用户模式指令预防（User-Mode Instruction Prevention）[6](@ref)
#define CR4_LA57_MASK (1UL << 12)       // 57位线性地址（5-Level Paging Enable）[6](@ref)
#define CR4_VMXE_MASK (1UL << 13)       // 虚拟机扩展（VMX Enable）[6,7](@ref)
#define CR4_SMXE_MASK (1UL << 14)       // 安全模式扩展（SMX Enable）[6](@ref)
#define CR4_PCIDE_MASK (1UL << 17)      // 进程上下文ID（Process-Context Identifier Enable）[6](@ref)
#define CR4_OSXSAVE_MASK (1UL << 18)    // AVX指令支持（OS Support for XSAVE/XRSTOR）[6,8](@ref)
#define CR4_PKE_MASK (1UL << 22)        // 保护密钥（Protection Key Enable）[6](@ref)

#include <stdint.h>

/**
 * x86 内部异常中断向量号枚举 (0~20)
 */
enum
{
  EXCEPTION_DE = 0,    ///< #DE: Divide Error (除零错误，Fault)
  EXCEPTION_DB = 1,    ///< #DB: Debug Exception (调试异常，Fault/Trap)
  EXCEPTION_NMI = 2,   ///< NMI: Non-Maskable Interrupt (不可屏蔽中断)
  EXCEPTION_BP = 3,    ///< #BP: Breakpoint (断点指令，Trap)
  EXCEPTION_OF = 4,    ///< #OF: Overflow (溢出检查，Trap)
  EXCEPTION_BR = 5,    ///< #BR: BOUND Range Exceeded (越界检查，Fault)
  EXCEPTION_UD = 6,    ///< #UD: Invalid Opcode (无效操作码，Fault)
  EXCEPTION_NM = 7,    ///< #NM: Device Not Available (协处理器不可用，Fault)
  EXCEPTION_DF = 8,    ///< #DF: Double Fault (双重故障，Abort)
  EXCEPTION_CSO = 9,   ///< #Coprocessor Segment Overrun (协处理器段越界，Fault，保留)
  EXCEPTION_TS = 10,   ///< #TS: Invalid TSS (无效任务状态段，Fault)
  EXCEPTION_NP = 11,   ///< #NP: Segment Not Present (段不存在，Fault)
  EXCEPTION_SS = 12,   ///< #SS: Stack Fault (栈段错误，Fault)
  EXCEPTION_GP = 13,   ///< #GP: General Protection (通用保护故障，Fault)
  EXCEPTION_PF = 14,   ///< #PF: Page Fault (缺页异常，Fault)
  EXCEPTION_RESV = 15, ///< Reserved (Intel 保留)
  EXCEPTION_MF = 16,   ///< #MF: x87 Floating-Point Exception (x87 浮点异常，Fault)
  EXCEPTION_AC = 17,   ///< #AC: Alignment Check (对齐检查，Fault)
  EXCEPTION_MC = 18,   ///< #MC: Machine Check (机器检查异常，Abort)
  EXCEPTION_XM = 19,   ///< #XM: SIMD Floating-Point Exception (SIMD 浮点异常，Fault)
  EXCEPTION_VE = 20    ///< #VE: Virtualization Exception (虚拟化异常，Fault)
};

#pragma pack(pop)

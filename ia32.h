#pragma once

#include <stdint.h>

#define CR0_PE_MASK 0x00000001 // 保护模式使能（Protection Enable）[1,2,4](@ref)
#define CR0_MP_MASK 0x00000002 // 协处理器监控（Monitor Coprocessor）[2,3,6](@ref)
#define CR0_EM_MASK 0x00000004 // 协处理器仿真（Emulation）[2,3,6](@ref)
#define CR0_TS_MASK 0x00000008 // 任务切换（Task Switched）[2,3,6](@ref)
#define CR0_ET_MASK 0x00000010 // 扩展类型（Extension Type，指示协处理器型号）[2,3,6](@ref)
#define CR0_NE_MASK 0x00000020 // 数值错误处理（Numeric Error）[1,2,6](@ref)
#define CR0_WP_MASK 0x00010000 // 写保护（Write Protect，控制只读页写入）[1,2,4](@ref)
#define CR0_AM_MASK 0x00040000 // 对齐检查（Alignment Mask）[1](@ref)
#define CR0_NW_MASK 0x20000000 // 非写透（Not Write-through，缓存写策略）[1](@ref)
#define CR0_CD_MASK 0x40000000 // 缓存禁用（Cache Disable）[1](@ref)
#define CR0_PG_MASK 0x80000000 // 分页使能（Paging Enable）[1,2,4](@ref)

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

enum xfeature
{
  XFEATURE_FP,
  XFEATURE_SSE,
  /*
   * Values above here are "legacy states".
   * Those below are "extended states".
   */
  XFEATURE_YMM,
  XFEATURE_BNDREGS,
  XFEATURE_BNDCSR,
  XFEATURE_OPMASK,
  XFEATURE_ZMM_Hi256,
  XFEATURE_Hi16_ZMM,
  XFEATURE_PT_UNIMPLEMENTED_SO_FAR,
  XFEATURE_PKRU,
  XFEATURE_PASID,
  XFEATURE_RSRVD_COMP_11,
  XFEATURE_RSRVD_COMP_12,
  XFEATURE_RSRVD_COMP_13,
  XFEATURE_RSRVD_COMP_14,
  XFEATURE_LBR,
  XFEATURE_RSRVD_COMP_16,
  XFEATURE_XTILE_CFG,
  XFEATURE_XTILE_DATA,

  XFEATURE_MAX,
};

#define XFEATURE_MASK_FP (1 << XFEATURE_FP)
#define XFEATURE_MASK_SSE (1 << XFEATURE_SSE)
#define XFEATURE_MASK_YMM (1 << XFEATURE_YMM)
#define XFEATURE_MASK_BNDREGS (1 << XFEATURE_BNDREGS)
#define XFEATURE_MASK_BNDCSR (1 << XFEATURE_BNDCSR)
#define XFEATURE_MASK_OPMASK (1 << XFEATURE_OPMASK)
#define XFEATURE_MASK_ZMM_Hi256 (1 << XFEATURE_ZMM_Hi256)
#define XFEATURE_MASK_Hi16_ZMM (1 << XFEATURE_Hi16_ZMM)
#define XFEATURE_MASK_PT (1 << XFEATURE_PT_UNIMPLEMENTED_SO_FAR)
#define XFEATURE_MASK_PKRU (1 << XFEATURE_PKRU)
#define XFEATURE_MASK_PASID (1 << XFEATURE_PASID)
#define XFEATURE_MASK_LBR (1 << XFEATURE_LBR)
#define XFEATURE_MASK_XTILE_CFG (1 << XFEATURE_XTILE_CFG)
#define XFEATURE_MASK_XTILE_DATA (1 << XFEATURE_XTILE_DATA)

#define XFEATURE_MASK_FPSSE (XFEATURE_MASK_FP | XFEATURE_MASK_SSE)
#define XFEATURE_MASK_AVX512 (XFEATURE_MASK_OPMASK | XFEATURE_MASK_ZMM_Hi256 | XFEATURE_MASK_Hi16_ZMM)
#define XFEATURE_MASK_XTILE (XFEATURE_MASK_XTILE_DATA | XFEATURE_MASK_XTILE_CFG)

#define MSR_ID_LOW_MIN 0x00000000
#define MSR_ID_LOW_MAX 0x00001FFF
#define MSR_ID_HIGH_MIN 0xC0000000
#define MSR_ID_HIGH_MAX 0xC0001FFF

#define MSR_APIC_BASE 0x01B
#define MSR_IA32_FEATURE_CONTROL 0x03A
#define MSR_IA32_SYSENTER_CS 0x174
#define MSR_IA32_SYSENTER_ESP 0x175
#define MSR_IA32_SYSENTER_EIP 0x176
#define MSR_IA32_DEBUGCTL 0x1D9
#define MSR_IA32_EFER 0xC0000080
#define MSR_IA32_LSTAR 0xC0000082
#define MSR_FS_BASE 0xC0000100
#define MSR_GS_BASE 0xC0000101
#define MSR_SHADOW_GS_BASE 0xC0000102
#define MSR_IA32_MTRR_CAP 0xFE
#define MSR_IA32_MTRR_DEF_TYPE 0x2FF
#define MSR_IA32_MTRR_PHYS_BASE 0x200
#define MSR_IA32_MTRR_PHYS_MASK 0x201
#define MSR_IA32_MTRR_FIX_64K_00000 0x250
#define MSR_IA32_MTRR_FIX_16K_80000 0x258
#define MSR_IA32_MTRR_FIX_16K_A0000 0x259
#define MSR_IA32_MTRR_FIX_4K_C0000 0x268
#define MSR_IA32_MTRR_FIX_4K_C8000 0x269
#define MSR_IA32_MTRR_FIX_4K_D0000 0x26A
#define MSR_IA32_MTRR_FIX_4K_D8000 0x26B
#define MSR_IA32_MTRR_FIX_4K_E0000 0x26C
#define MSR_IA32_MTRR_FIX_4K_E8000 0x26D
#define MSR_IA32_MTRR_FIX_4K_F0000 0x26E
#define MSR_IA32_MTRR_FIX_4K_F8000 0x26F

typedef union
{
  struct
  {
    uint64_t lock_bit : 1;
    uint64_t enable_vmx_inside_smx : 1;
    uint64_t enable_vmx_outside_smx : 1;
    uint64_t reserved_1 : 5;
    uint64_t senter_local_function_enables : 7;
    uint64_t senter_global_enable : 1;
    uint64_t reserved_2 : 1;
    uint64_t sgx_launch_control_enable : 1;
    uint64_t sgx_global_enable : 1;
    uint64_t reserved_3 : 1;
    uint64_t lmce_on : 1;
  };

  uint64_t all;
} ia32_feature_control_register_t;

#define SEGMENT_DATA_RO 0x0
#define SEGMENT_DATA_RO_ACCESSED 0x1
#define SEGMENT_DATA_RW 0x2
#define SEGMENT_DATA_RW_ACCESSED 0x3
#define SEGMENT_DATA_RO_XDOWN 0x4
#define SEGMENT_DATA_RO_XDOWN_ACCESSED 0x5
#define SEGMENT_DATA_RW_XDOWN 0x6
#define SEGMENT_DATA_RW_XDOWN_ACCESSED 0x7

#define SEGMENT_CODE_XO 0x8
#define SEGMENT_CODE_XO_ACCESSED 0x9
#define SEGMENT_CODE_RX 0xA
#define SEGMENT_CODE_RX_ACCESSED 0xB
#define SEGMENT_CODE_XO_CFORM 0xC
#define SEGMENT_CODE_XO_CFORM_ACCESSED 0xD
#define SEGMENT_CODE_RX_CFORM 0xE
#define SEGMENT_CODE_RX_CFORM_ACCESSED 0xF

#define SEGMENT_SYSTEM_16BIT_TSS_AVAIL 1
#define SEGMENT_SYSTEM_LDT 2
#define SEGMENT_SYSTEM_16BIT_TSS_BUSY 3
#define SEGMENT_SYSTEM_16BIT_CALL_GATE 4
#define SEGMENT_SYSTEM_TASK_GATE 5
#define SEGMENT_SYSTEM_16BIT_INT_GATE 6
#define SEGMENT_SYSTEM_16BIT_TRAP_GATE 7
#define SEGMENT_SYSTEM_32BIT_TSS_AVAIL 9
#define SEGMENT_SYSTEM_32BIT_TSS_BUSY 11
#define SEGMENT_SYSTEM_32BIT_CALL_GATE 12
#define SEGMENT_SYSTEM_32BIT_INT_GATE 14
#define SEGMENT_SYSTEM_32BIT_TRAP_GATE 15

enum
{
  DIVIDE_ERROR = 0x00000000,
  DEBUG = 0x00000001,
  NMI = 0x00000002,
  BREAKPOINT = 0x00000003,
  OVERFLOW = 0x00000004,
  BOUND_RANGE_EXCEEDED = 0x00000005,
  INVALID_OPCODE = 0x00000006,
  DEVICE_NOT_AVAILABLE = 0x00000007,
  DOUBLE_FAULT = 0x00000008,
  COPROCESSOR_SEGMENT_OVERRUN = 0x00000009,
  INVALID_TSS = 0x0000000A,
  SEGMENT_NOT_PRESENT = 0x0000000B,
  STACK_SEGMENT_FAULT = 0x0000000C,
  GENERAL_PROTECTION = 0x0000000D,
  PAGE_FAULT = 0x0000000E,
  X87_FLOATING_POINT_ERROR = 0x00000010,
  ALIGNMENT_CHECK = 0x00000011,
  MACHINE_CHECK = 0x00000012,
  SIMD_FLOATING_POINT_ERROR = 0x00000013,
  VIRTUALIZATION_EXCEPTION = 0x00000014,
  CONTROL_PROTECTION = 0x00000015,
};

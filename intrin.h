#pragma once
#include <stdint.h>

#define PAGE_SIZE 4096
#define ALIGN_UP(val, align) (((val) + (align) - 1) & ~((align) - 1))
#define PAGE_ALIGN_UP(val) ALIGN_UP(val, PAGE_SIZE)
#define PAGE_SHIFT 12

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

#pragma pack(push, 1)

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

typedef struct
{
    uint16_t limit; // 限长
    uint64_t base;  // 基址
} gdtr_t, idtr_t;

typedef struct
{
    uint16_t segment_limit_low;
    uint16_t base_address_low;
    uint32_t base_address_middle : 8;
    uint32_t type : 4;
    uint32_t descriptor_type : 1;
    uint32_t descriptor_privilege_level : 2;
    uint32_t present : 1;
    uint32_t segment_limit_high : 4;
    uint32_t available_bit : 1;
    uint32_t long_mode : 1;
    uint32_t default_big : 1;
    uint32_t granularity : 1;
    uint32_t base_address_high : 8;
} segment_desc_t;

typedef struct
{
    uint16_t segment_limit_low;
    uint16_t base_address_low;
    uint32_t base_address_middle : 8;
    uint32_t type : 4;
    uint32_t descriptor_type : 1;
    uint32_t descriptor_privilege_level : 2;
    uint32_t present : 1;
    uint32_t segment_limit_high : 4;
    uint32_t available_bit : 1;
    uint32_t long_mode : 1;
    uint32_t default_big : 1;
    uint32_t granularity : 1;
    uint32_t base_address_high : 8;
    uint32_t base_address_upper;
    uint32_t must_be_zero;
} segment_desc64_t;

typedef struct
{
    uint32_t reserved_0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved_1;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved_2;
    uint16_t reserved_3;
    uint16_t io_map_base;
} tss_t;

typedef struct
{
    uint16_t offset_low;
    uint16_t segment_selector;
    uint32_t interrupt_stack_table : 3;
    uint32_t must_be_zero_0 : 5;
    uint32_t type : 4;
    uint32_t must_be_zero_1 : 1;
    uint32_t descriptor_privilege_level : 2;
    uint32_t present : 1;
    uint32_t offset_middle : 16;
    uint32_t offset_high;
    uint32_t reserved;
} gate_desc_t;

typedef union
{
    struct
    {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved_1 : 1;
        uint64_t must_be_zero : 1;
        uint64_t ignored_1 : 3;
        uint64_t restart : 1;
        uint64_t page_frame_number : 36;
        uint64_t reserved_2 : 4;
        uint64_t ignored_2 : 11;
        uint64_t execute_disable : 1;
    };

    uint64_t all;
} pml4e_t;

typedef union
{
    struct
    {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t large_page : 1;
        uint64_t global : 1;
        uint64_t ignored_1 : 2;
        uint64_t restart : 1;
        uint64_t pat : 1;
        uint64_t reserved_1 : 17;
        uint64_t page_frame_number : 18;
        uint64_t reserved_2 : 4;
        uint64_t ignored_2 : 7;
        uint64_t protection_key : 4;
        uint64_t execute_disable : 1;
    };
    uint64_t all;
} large_pdpte_t;

typedef union
{
    struct
    {
        uint64_t present : 1;
        uint64_t write : 1;
        uint64_t supervisor : 1;
        uint64_t page_level_write_through : 1;
        uint64_t page_level_cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved_1 : 1;
        uint64_t large_page : 1;
        uint64_t ignored_1 : 3;
        uint64_t restart : 1;
        uint64_t page_frame_number : 36;
        uint64_t reserved_2 : 4;
        uint64_t ignored_2 : 11;
        uint64_t execute_disable : 1;
    };
    large_pdpte_t large;
    uint64_t all;
} pdpte_t;

#pragma pack(pop)

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

// 控制寄存器
uint64_t read_cr0(void);
void write_cr0(uint64_t value);
uint64_t read_cr2(void); // 缺页地址寄存器
uint64_t write_cr2(uint64_t value);
uint64_t read_cr3(void); // 页目录基址寄存器
uint64_t write_cr3(uint64_t value);
uint64_t read_cr4(void);
void write_cr4(uint64_t value);

// GDTR/IDTR寄存器操作
void read_gdtr(uint64_t addr);
void write_gdtr(uint64_t addr);
void read_idtr(uint64_t addr);
void write_idtr(uint64_t addr);

// MSR操作
uint64_t read_msr(uint32_t index);
void write_msr(uint32_t index, uint64_t value);

// 段寄存器（只读）
uint16_t read_cs(void); // 代码段寄存器
uint16_t read_ds(void); // 数据段寄存器
uint16_t read_es(void); // 附加段寄存器
uint16_t read_fs(void); // FS段寄存器（Linux用于线程局部存储）
uint16_t read_gs(void); // GS段寄存器（x86-64用于内核数据）
uint16_t read_ss(void); // 栈段寄存器
uint16_t read_tr(void); // 任务寄存器

// dr寄存器操作
uint64_t read_dr0(void);
uint64_t read_dr1(void);
uint64_t read_dr2(void);
uint64_t read_dr3(void);
uint64_t read_dr6(void); // 调试状态寄存器
uint64_t read_dr7(void); // 调试控制寄存器
void write_dr0(uint64_t value);
void write_dr1(uint64_t value);
void write_dr2(uint64_t value);
void write_dr3(uint64_t value);
void write_dr6(uint64_t value);
void write_dr7(uint64_t value);

uint32_t read_cs_access_rights(void); // 读取CS访问权限字节
uint32_t read_ds_access_rights(void); // 读取DS访问权限字节
uint32_t read_es_access_rights(void); // 读取ES访问权限字节
uint32_t read_fs_access_rights(void); // 读取FS访问权限字节
uint32_t read_gs_access_rights(void); // 读取GS访问权限字节
uint32_t read_ss_access_rights(void); // 读取SS访问权限字节
uint32_t read_tr_access_rights(void); // 读取TSS访问权限字节

uint64_t read_rflags(void);

void out_byte(uint16_t port, uint8_t value);
uint8_t in_byte(uint16_t port);

void wbinvd_wrapper();

void disable_interrupt();

void cpuid_wrapper(uint64_t *rax, uint64_t *rcx, uint64_t *rdx, uint64_t *rbx);

void xsetbv(uint32_t index, uint64_t value);

uint64_t read_tsc(void);
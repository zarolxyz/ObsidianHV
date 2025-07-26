#pragma once

#include <stdint.h>
#include "intrin.h"

#pragma pack(push, 1)

typedef struct
{
  uint32_t revision_id;
  uint8_t data[PAGE_SIZE - 4];
} vmxon_t;

typedef struct
{
  uint32_t revision_id;
  uint32_t abort_indicator;
  uint8_t data[PAGE_SIZE - 8];
} vmcs_t;

typedef struct
{
  uint8_t read_low[1024];
  uint8_t read_high[1024];
  uint8_t write_low[1024];
  uint8_t write_high[1024];
} msr_bitmap_t;

#pragma pack(pop)

#define MSR_IA32_VMX_BASIC 0x480
#define MSR_IA32_VMX_MISC 0x485
#define MSR_IA32_VMX_CR0_FIXED0 0x486
#define MSR_IA32_VMX_CR0_FIXED1 0x487
#define MSR_IA32_VMX_CR4_FIXED0 0x488
#define MSR_IA32_VMX_CR4_FIXED1 0x489
#define MSR_IA32_VMX_VMCS_ENUM 0x48A
#define MSR_IA32_VMX_PROCBASED_CTLS2 0x48B
#define MSR_IA32_VMX_EPT_VPID_CAP 0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS 0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS 0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS 0x490
#define MSR_IA32_VMX_VMFUNC 0x491

#define VMX_BASIC_REVISION_MASK 0x7fffffff
#define VMX_BASIC_TRUE_CONTROLS (1ULL << 55)

#define CPU_BASED_VIRTUAL_INTR_PENDING 0x00000004
#define CPU_BASED_USE_TSC_OFFSETING 0x00000008
#define CPU_BASED_HLT_EXITING 0x00000080
#define CPU_BASED_INVLPG_EXITING 0x00000200
#define CPU_BASED_MWAIT_EXITING 0x00000400
#define CPU_BASED_RDPMC_EXITING 0x00000800
#define CPU_BASED_RDTSC_EXITING 0x00001000
#define CPU_BASED_CR3_LOAD_EXITING 0x00008000
#define CPU_BASED_CR3_STORE_EXITING 0x00010000
#define CPU_BASED_CR8_LOAD_EXITING 0x00080000
#define CPU_BASED_CR8_STORE_EXITING 0x00100000
#define CPU_BASED_TPR_SHADOW 0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING 0x00400000
#define CPU_BASED_MOV_DR_EXITING 0x00800000
#define CPU_BASED_UNCOND_IO_EXITING 0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP 0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG 0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP 0x10000000
#define CPU_BASED_MONITOR_EXITING 0x20000000
#define CPU_BASED_PAUSE_EXITING 0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS 0x80000000

#define PIN_BASED_EXT_INTR_MASK 0x00000001
#define PIN_BASED_NMI_EXITING 0x00000008
#define PIN_BASED_VIRTUAL_NMIS 0x00000020
#define PIN_BASED_PREEMPT_TIMER 0x00000040
#define PIN_BASED_POSTED_INTERRUPT 0x00000080

#define VM_EXIT_SAVE_DEBUG_CONTROLS 0x00000004
#define VM_EXIT_HOST_ADDR_SPACE_SIZE 0x00000200
#define VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL 0x00001000
#define VM_EXIT_ACK_INTR_ON_EXIT 0x00008000
#define VM_EXIT_SAVE_IA32_PAT 0x00040000
#define VM_EXIT_LOAD_IA32_PAT 0x00080000
#define VM_EXIT_SAVE_IA32_EFER 0x00100000
#define VM_EXIT_LOAD_IA32_EFER 0x00200000
#define VM_EXIT_SAVE_VMX_PREEMPTION_TIMER 0x00400000
#define VM_EXIT_CLEAR_BNDCFGS 0x00800000
#define VM_EXIT_PT_CONCEAL_PIP 0x01000000
#define VM_EXIT_CLEAR_IA32_RTIT_CTL 0x02000000
#define VM_EXIT_CLEAR_IA32_LBR_CTL 0x04000000

#define VM_ENTRY_LOAD_DEBUG_CONTROLS 0x00000004
#define VM_ENTRY_IA32E_MODE 0x00000200
#define VM_ENTRY_SMM 0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR 0x00000800
#define VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL 0x00002000
#define VM_ENTRY_LOAD_IA32_PAT 0x00004000
#define VM_ENTRY_LOAD_IA32_EFER 0x00008000
#define VM_ENTRY_LOAD_BNDCFGS 0x00010000
#define VM_ENTRY_PT_CONCEAL_PIP 0x00020000
#define VM_ENTRY_LOAD_IA32_RTIT_CTL 0x00040000
#define VM_ENTRY_LOAD_IA32_LBR_CTL 0x00200000

#define SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES 0x00000001
#define SECONDARY_EXEC_ENABLE_EPT 0x00000002
#define SECONDARY_EXEC_DESCRIPTOR_TABLE_EXITING 0x00000004
#define SECONDARY_EXEC_ENABLE_RDTSCP 0x00000008
#define SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE 0x00000010
#define SECONDARY_EXEC_ENABLE_VPID 0x00000020
#define SECONDARY_EXEC_WBINVD_EXITING 0x00000040
#define SECONDARY_EXEC_UNRESTRICTED_GUEST 0x00000080
#define SECONDARY_EXEC_APIC_REGISTER_VIRT 0x00000100
#define SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY 0x00000200
#define SECONDARY_EXEC_PAUSE_LOOP_EXITING 0x00000400
#define SECONDARY_EXEC_ENABLE_INVPCID 0x00001000
#define SECONDARY_EXEC_ENABLE_VM_FUNCTIONS 0x00002000
#define SECONDARY_EXEC_ENABLE_VMCS_SHADOWING 0x00004000
#define SECONDARY_EXEC_ENABLE_ENCLS_EXITING 0x00008000
#define SECONDARY_EXEC_ENABLE_PML 0x00020000
#define SECONDARY_EXEC_ENABLE_VIRT_EXCEPTIONS 0x00040000
#define SECONDARY_EXEC_PT_CONCEAL_VMX 0x00080000
#define SECONDARY_EXEC_ENABLE_XSAVES_XSTORS 0x00100000
#define SECONDARY_EXEC_PCOMMIT 0x00200000
#define SECONDARY_EXEC_USE_GPA_FOR_INTEL_PT 0x01000000
#define SECONDARY_EXEC_TSC_SCALING 0x02000000

enum VMCS_FIELD
{
  VIRTUAL_PROCESSOR_ID = 0x00000000, // 16-Bit Control Field
  POSTED_INTERRUPT_NOTIFICATION = 0x00000002,
  EPTP_INDEX = 0x00000004,
  GUEST_ES_SELECTOR = 0x00000800, // 16-Bit Guest-State Fields
  GUEST_CS_SELECTOR = 0x00000802,
  GUEST_SS_SELECTOR = 0x00000804,
  GUEST_DS_SELECTOR = 0x00000806,
  GUEST_FS_SELECTOR = 0x00000808,
  GUEST_GS_SELECTOR = 0x0000080a,
  GUEST_LDTR_SELECTOR = 0x0000080c,
  GUEST_TR_SELECTOR = 0x0000080e,
  GUEST_INTERRUPT_STATUS = 0x00000810,
  HOST_ES_SELECTOR = 0x00000c00, // 16-Bit Host-State Fields
  HOST_CS_SELECTOR = 0x00000c02,
  HOST_SS_SELECTOR = 0x00000c04,
  HOST_DS_SELECTOR = 0x00000c06,
  HOST_FS_SELECTOR = 0x00000c08,
  HOST_GS_SELECTOR = 0x00000c0a,
  HOST_TR_SELECTOR = 0x00000c0c,
  IO_BITMAP_A = 0x00002000, // 64-Bit Control Fields
  IO_BITMAP_A_HIGH = 0x00002001,
  IO_BITMAP_B = 0x00002002,
  IO_BITMAP_B_HIGH = 0x00002003,
  MSR_BITMAP = 0x00002004,
  MSR_BITMAP_HIGH = 0x00002005,
  VM_EXIT_MSR_STORE_ADDR = 0x00002006,
  VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
  VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
  VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
  VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
  VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
  EXECUTIVE_VMCS_POINTER = 0x0000200c,
  EXECUTIVE_VMCS_POINTER_HIGH = 0x0000200d,
  TSC_OFFSET = 0x00002010,
  TSC_OFFSET_HIGH = 0x00002011,
  VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
  VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
  APIC_ACCESS_ADDR = 0x00002014,
  APIC_ACCESS_ADDR_HIGH = 0x00002015,
  EPT_POINTER = 0x0000201a,
  EPT_POINTER_HIGH = 0x0000201b,
  EOI_EXIT_BITMAP_0 = 0x0000201c,
  EOI_EXIT_BITMAP_0_HIGH = 0x0000201d,
  EOI_EXIT_BITMAP_1 = 0x0000201e,
  EOI_EXIT_BITMAP_1_HIGH = 0x0000201f,
  EOI_EXIT_BITMAP_2 = 0x00002020,
  EOI_EXIT_BITMAP_2_HIGH = 0x00002021,
  EOI_EXIT_BITMAP_3 = 0x00002022,
  EOI_EXIT_BITMAP_3_HIGH = 0x00002023,
  EPTP_LIST_ADDRESS = 0x00002024,
  EPTP_LIST_ADDRESS_HIGH = 0x00002025,
  VMREAD_BITMAP_ADDRESS = 0x00002026,
  VMREAD_BITMAP_ADDRESS_HIGH = 0x00002027,
  VMWRITE_BITMAP_ADDRESS = 0x00002028,
  VMWRITE_BITMAP_ADDRESS_HIGH = 0x00002029,
  VIRTUALIZATION_EXCEPTION_INFO_ADDDRESS = 0x0000202a,
  VIRTUALIZATION_EXCEPTION_INFO_ADDDRESS_HIGH = 0x0000202b,
  XSS_EXITING_BITMAP = 0x0000202c,
  XSS_EXITING_BITMAP_HIGH = 0x0000202d,
  GUEST_PHYSICAL_ADDRESS = 0x00002400, // 64-Bit Read-Only Data Field
  GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,
  VMCS_LINK_POINTER = 0x00002800, // 64-Bit Guest-State Fields
  VMCS_LINK_POINTER_HIGH = 0x00002801,
  GUEST_IA32_DEBUGCTL = 0x00002802,
  GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
  GUEST_IA32_PAT = 0x00002804,
  GUEST_IA32_PAT_HIGH = 0x00002805,
  GUEST_IA32_EFER = 0x00002806,
  GUEST_IA32_EFER_HIGH = 0x00002807,
  GUEST_IA32_PERF_GLOBAL_CTRL = 0x00002808,
  GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002809,
  GUEST_PDPTR0 = 0x0000280a,
  GUEST_PDPTR0_HIGH = 0x0000280b,
  GUEST_PDPTR1 = 0x0000280c,
  GUEST_PDPTR1_HIGH = 0x0000280d,
  GUEST_PDPTR2 = 0x0000280e,
  GUEST_PDPTR2_HIGH = 0x0000280f,
  GUEST_PDPTR3 = 0x00002810,
  GUEST_PDPTR3_HIGH = 0x00002811,
  GUEST_IA32_BOUND_CONFIG = 0x2812,
  GUEST_IA32_RTIT_CTRL = 0x2814,
  GUEST_IA32_LBR_CTL = 0x2816,
  GUEST_IA32_PKRS = 0x2818,
  HOST_IA32_PAT = 0x00002c00, // 64-Bit Host-State Fields
  HOST_IA32_PAT_HIGH = 0x00002c01,
  HOST_IA32_EFER = 0x00002c02,
  HOST_IA32_EFER_HIGH = 0x00002c03,
  HOST_IA32_PERF_GLOBAL_CTRL = 0x00002c04,
  HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002c05,
  PIN_BASED_VM_EXEC_CONTROL = 0x00004000, // 32-Bit Control Fields
  CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
  EXCEPTION_BITMAP = 0x00004004,
  PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
  PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
  CR3_TARGET_COUNT = 0x0000400a,
  VM_EXIT_CONTROLS = 0x0000400c,
  VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
  VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
  VM_ENTRY_CONTROLS = 0x00004012,
  VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
  VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
  VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
  VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
  TPR_THRESHOLD = 0x0000401c,
  SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
  PLE_GAP = 0x00004020,
  PLE_WINDOW = 0x00004022,
  VM_INSTRUCTION_ERROR = 0x00004400, // 32-Bit Read-Only Data Fields
  VM_EXIT_REASON = 0x00004402,
  VM_EXIT_INTR_INFO = 0x00004404,
  VM_EXIT_INTR_ERROR_CODE = 0x00004406,
  IDT_VECTORING_INFO_FIELD = 0x00004408,
  IDT_VECTORING_ERROR_CODE = 0x0000440a,
  VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
  VMX_INSTRUCTION_INFO = 0x0000440e,
  GUEST_ES_LIMIT = 0x00004800, // 32-Bit Guest-State Fields
  GUEST_CS_LIMIT = 0x00004802,
  GUEST_SS_LIMIT = 0x00004804,
  GUEST_DS_LIMIT = 0x00004806,
  GUEST_FS_LIMIT = 0x00004808,
  GUEST_GS_LIMIT = 0x0000480a,
  GUEST_LDTR_LIMIT = 0x0000480c,
  GUEST_TR_LIMIT = 0x0000480e,
  GUEST_GDTR_LIMIT = 0x00004810,
  GUEST_IDTR_LIMIT = 0x00004812,
  GUEST_ES_AR_BYTES = 0x00004814,
  GUEST_CS_AR_BYTES = 0x00004816,
  GUEST_SS_AR_BYTES = 0x00004818,
  GUEST_DS_AR_BYTES = 0x0000481a,
  GUEST_FS_AR_BYTES = 0x0000481c,
  GUEST_GS_AR_BYTES = 0x0000481e,
  GUEST_LDTR_AR_BYTES = 0x00004820,
  GUEST_TR_AR_BYTES = 0x00004822,
  GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
  GUEST_ACTIVITY_STATE = 0x00004826,
  GUEST_SMBASE = 0x00004828,
  GUEST_SYSENTER_CS = 0x0000482a,
  VMX_PREEMPTION_TIMER_VALUE = 0x0000482e,
  HOST_IA32_SYSENTER_CS = 0x00004c00, // 32-Bit Host-State Field
  CR0_GUEST_HOST_MASK = 0x00006000,   // Natural-Width Control Fields
  CR4_GUEST_HOST_MASK = 0x00006002,
  CR0_READ_SHADOW = 0x00006004,
  CR4_READ_SHADOW = 0x00006006,
  CR3_TARGET_VALUE0 = 0x00006008,
  CR3_TARGET_VALUE1 = 0x0000600a,
  CR3_TARGET_VALUE2 = 0x0000600c,
  CR3_TARGET_VALUE3 = 0x0000600e,
  EXIT_QUALIFICATION = 0x00006400, // Natural-Width Read-Only Data Fields
  IO_RCX = 0x00006402,
  IO_RSI = 0x00006404,
  IO_RDI = 0x00006406,
  IO_RIP = 0x00006408,
  GUEST_LINEAR_ADDRESS = 0x0000640a,
  GUEST_CR0 = 0x00006800, // Natural-Width Guest-State Fields
  GUEST_CR3 = 0x00006802,
  GUEST_CR4 = 0x00006804,
  GUEST_ES_BASE = 0x00006806,
  GUEST_CS_BASE = 0x00006808,
  GUEST_SS_BASE = 0x0000680a,
  GUEST_DS_BASE = 0x0000680c,
  GUEST_FS_BASE = 0x0000680e,
  GUEST_GS_BASE = 0x00006810,
  GUEST_LDTR_BASE = 0x00006812,
  GUEST_TR_BASE = 0x00006814,
  GUEST_GDTR_BASE = 0x00006816,
  GUEST_IDTR_BASE = 0x00006818,
  GUEST_DR7 = 0x0000681a,
  GUEST_RSP = 0x0000681c,
  GUEST_RIP = 0x0000681e,
  GUEST_RFLAGS = 0x00006820,
  GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
  GUEST_SYSENTER_ESP = 0x00006824,
  GUEST_SYSENTER_EIP = 0x00006826,
  HOST_CR0 = 0x00006c00, // Natural-Width Host-State Fields
  HOST_CR3 = 0x00006c02,
  HOST_CR4 = 0x00006c04,
  HOST_FS_BASE = 0x00006c06,
  HOST_GS_BASE = 0x00006c08,
  HOST_TR_BASE = 0x00006c0a,
  HOST_GDTR_BASE = 0x00006c0c,
  HOST_IDTR_BASE = 0x00006c0e,
  HOST_IA32_SYSENTER_ESP = 0x00006c10,
  HOST_IA32_SYSENTER_EIP = 0x00006c12,
  HOST_RSP = 0x00006c14,
  HOST_RIP = 0x00006c16,
};

enum EXIT_REASON
{
  EXIT_REASON_EXCEPTION_NMI = 0,      // Exception or non-maskable interrupt (NMI).
  EXIT_REASON_EXTERNAL_INTERRUPT = 1, // External interrupt.
  EXIT_REASON_TRIPLE_FAULT = 2,       // Triple fault.
  EXIT_REASON_INIT = 3,               // INIT signal.
  EXIT_REASON_SIPI = 4,               // Start-up IPI (SIPI).
  EXIT_REASON_IO_SMI = 5,             // I/O system-management interrupt (SMI).
  EXIT_REASON_OTHER_SMI = 6,          // Other SMI.
  EXIT_REASON_PENDING_INTERRUPT = 7,  // Interrupt window exiting.
  EXIT_REASON_NMI_WINDOW = 8,         // NMI window exiting.
  EXIT_REASON_TASK_SWITCH = 9,        // Task switch.
  EXIT_REASON_CPUID = 10,             // Guest software attempted to execute CPUID.
  EXIT_REASON_GETSEC = 11,            // Guest software attempted to execute GETSEC.
  EXIT_REASON_HLT = 12,               // Guest software attempted to execute HLT.
  EXIT_REASON_INVD = 13,              // Guest software attempted to execute INVD.
  EXIT_REASON_INVLPG = 14,            // Guest software attempted to execute INVLPG.
  EXIT_REASON_RDPMC = 15,             // Guest software attempted to execute RDPMC.
  EXIT_REASON_RDTSC = 16,             // Guest software attempted to execute RDTSC.
  EXIT_REASON_RSM = 17,               // Guest software attempted to execute RSM in SMM.
  EXIT_REASON_VMCALL = 18,            // Guest software executed VMCALL.
  EXIT_REASON_VMCLEAR = 19,           // Guest software executed VMCLEAR.
  EXIT_REASON_VMLAUNCH = 20,          // Guest software executed VMLAUNCH.
  EXIT_REASON_VMPTRLD = 21,           // Guest software executed VMPTRLD.
  EXIT_REASON_VMPTRST = 22,           // Guest software executed VMPTRST.
  EXIT_REASON_VMREAD = 23,            // Guest software executed VMREAD.
  EXIT_REASON_VMRESUME = 24,          // Guest software executed VMRESUME.
  EXIT_REASON_VMWRITE = 25,           // Guest software executed VMWRITE.
  EXIT_REASON_VMXOFF = 26,            // Guest software executed VMXOFF.
  EXIT_REASON_VMXON = 27,             // Guest software executed VMXON.
  EXIT_REASON_CR_ACCESS = 28,         // Control-register accesses.
  EXIT_REASON_DR_ACCESS = 29,         // Debug-register accesses.
  EXIT_REASON_IO_INSTRUCTION = 30,    // I/O instruction.
  EXIT_REASON_MSR_READ =
      31, // RDMSR. Guest software attempted to execute RDMSR.
  EXIT_REASON_MSR_WRITE =
      32, // WRMSR. Guest software attempted to execute WRMSR.
  EXIT_REASON_INVALID_GUEST_STATE =
      33,                             // VM-entry failure due to invalid guest state.
  EXIT_REASON_MSR_LOADING = 34,       // VM-entry failure due to MSR loading.
  EXIT_REASON_RESERVED_35 = 35,       // Reserved
  EXIT_REASON_MWAIT_INSTRUCTION = 36, // Guest software executed MWAIT.
  EXIT_REASOM_MTF = 37,               // VM-exit due to monitor trap flag.
  EXIT_REASON_RESERVED_38 = 38,       // Reserved
  EXIT_REASON_MONITOR_INSTRUCTION =
      39, // Guest software attempted to execute MONITOR.
  EXIT_REASON_PAUSE_INSTRUCTION =
      40,                         // Guest software attempted to execute PAUSE.
  EXIT_REASON_MACHINE_CHECK = 41, // VM-entry failure due to machine-check.
  EXIT_REASON_RESERVED_42 = 42,   // Reserved
  EXIT_REASON_TPR_BELOW_THRESHOLD =
      43, // TPR below threshold. Guest software executed MOV to CR8.
  EXIT_REASON_APIC_ACCESS =
      44, // APIC access. Guest software attempted to access memory at a
          // physical address on the APIC-access page.
  EXIT_REASON_VIRTUALIZED_EIO =
      45, // EOI virtualization was performed for a virtual interrupt whose
          // vector indexed a bit set in the EOIexit bitmap
  EXIT_REASON_XDTR_ACCESS =
      46, // Guest software attempted to execute LGDT, LIDT, SGDT, or SIDT.
  EXIT_REASON_TR_ACCESS =
      47, // Guest software attempted to execute LLDT, LTR, SLDT, or STR.
  EXIT_REASON_EPT_VIOLATION =
      48, // An attempt to access memory with a guest-physical address was
          // disallowed by the configuration of the EPT paging structures.
  EXIT_REASON_EPT_MISCONFIG =
      49,                         // An attempt to access memory with a guest-physical address
                                  // encountered a misconfigured EPT paging-structure entry.
  EXIT_REASON_INVEPT = 50,        // Guest software attempted to execute INVEPT.
  EXIT_REASON_RDTSCP = 51,        // Guest software attempted to execute RDTSCP.
  EXIT_REASON_PREEMPT_TIMER = 52, // VMX-preemption timer expired. The
                                  // preemption timer counted down to zero.
  EXIT_REASON_INVVPID = 53,       // Guest software attempted to execute INVVPID.
  EXIT_REASON_WBINVD = 54,        // Guest software attempted to execute WBINVD
  EXIT_REASON_XSETBV = 55,        // Guest software attempted to execute XSETBV.
  EXIT_REASON_APIC_WRITE = 56,    // Guest completed write to virtual-APIC.
  EXIT_REASON_RDRAND = 57,        // Guest software attempted to execute RDRAND.
  EXIT_REASON_INVPCID = 58,       // Guest software attempted to execute INVPCID.
  EXIT_REASON_VMFUNC = 59,        // Guest software attempted to execute VMFUNC.
  EXIT_REASON_RESERVED_60 = 60,   // Reserved
  EXIT_REASON_RDSEED = 61,        // Guest software attempted to executed RDSEED and
                                  // exiting was enabled.
  EXIT_REASON_RESERVED_62 = 62,   // Reserved
  EXIT_REASON_XSAVES = 63,        // Guest software attempted to executed XSAVES and
                                  // exiting was enabled.
  EXIT_REASON_XRSTORS = 64,       // Guest software attempted to executed XRSTORS and
                                  // exiting was enabled.

  VMX_MAX_GUEST_VMEXIT = 65
};

typedef union
{
  uint32_t all;
  struct
  {
    uint32_t vector : 8;             //!< [0:7]
    uint32_t interruption_type : 3;  //!< [8:10]
    uint32_t deliver_error_code : 1; //!< [11]
    uint32_t reserved : 19;          //!< [12:30]
    uint32_t valid : 1;              //!< [31]
  } fields;
} vm_entry_interruption_info_t;

#define VMX_INTR_TYPE_HWINTR 0           // 外部中断
#define VMX_INTR_TYPE_NMI 2              // NMI
#define VMX_INTR_TYPE_HWEXCEPTION 3      // 硬件异常
#define VMX_INTR_TYPE_SWINTR 4           // 软件中断
#define VMX_INTR_TYPE_PRIV_SWEXCEPTION 6 // 特权软件异常
#define VMX_INTR_TYPE_SWEXCEPTION 7      // 软件异常

#define GUEST_ACTIVITY_ACTIVE 0
#define GUEST_ACTIVITY_HLT 1
#define GUEST_ACTIVITY_SHUTDOWN 2
#define GUEST_ACTIVITY_WAIT_SIPI 3

typedef union
{
  struct
  {
    uint32_t segment_type : 4;
    uint32_t descriptor_type : 1;
    uint32_t dpl : 2;
    uint32_t present : 1;
    uint32_t reserved0 : 4;
    uint32_t avl : 1;
    uint32_t long_mode : 1;
    uint32_t op_size : 1;
    uint32_t granularity : 1;
    uint32_t unusable : 1;
    uint32_t reserved1 : 15;
  };
  uint32_t all;
} vmx_segment_ar_t;

uint32_t vmxon(uint64_t *vmxon_region_phy);
uint32_t vmclear(uint64_t *vmcs_region_phy);
uint32_t vmptrld(uint64_t *vmcs_region_phy);
uint32_t vmptrst(uint64_t *vmcs_region_phy);
uint64_t vmread(uint64_t field);
void vmwrite(uint64_t field, uint64_t value);
uint32_t vmxoff(void);
void invvpid_single(uint16_t vpid);
void invept_single(uint64_t eptp);

int vmx_check_cpuid();
int vmx_check_feature_control();
uint64_t vmx_ajust_cr0(uint64_t value);
uint64_t vmx_ajust_cr4(uint64_t value);
void msr_bitmap_set_read(msr_bitmap_t *msr_bitmap, uint32_t index);
void msr_bitmap_set_write(msr_bitmap_t *msr_bitmap, uint32_t index);
void init_msr_bitmap(msr_bitmap_t *msr_bitmap);
uint32_t vmx_adjust_control_value(uint32_t msr_index, uint32_t control_value);
void vmx_set_control_field(uint32_t field, uint64_t control);
uint32_t vmx_convert_access_rights(uint32_t access_rights);
void vmx_inject_interruption(int type, int vector);
void vmx_inject_interruption_error_code(int type, int vector, uint32_t error_code);
void vmx_advance_rip();
void vmx_inject_ud();
void vmx_inject_gp(uint32_t error_code);
void vmx_guest_exit_ia32e();

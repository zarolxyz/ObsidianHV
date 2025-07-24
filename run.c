#include "run.h"
#include "vmx.h"
#include "intrin.h"
#include "ia32.h"

// 此模块负责处理 VM EXIT

void dump_regs(regs_t *regs)
{
    PRINTF("RAX: 0x%x\n", regs->rax);
    PRINTF("RCX: 0x%x\n", regs->rcx);
    PRINTF("RDX: 0x%x\n", regs->rdx);
    PRINTF("RBX: 0x%x\n", regs->rbx);
    PRINTF("RBP: 0x%x\n", regs->rbp);
    PRINTF("RSI: 0x%x\n", regs->rsi);
    PRINTF("RDI: 0x%x\n", regs->rdi);
    PRINTF("R8: 0x%x\n", regs->r8);
    PRINTF("R9: 0x%x\n", regs->r9);
    PRINTF("R10: 0x%x\n", regs->r10);
    PRINTF("R11: 0x%x\n", regs->r11);
    PRINTF("R12: 0x%x\n", regs->r12);
    PRINTF("R13: 0x%x\n", regs->r13);
    PRINTF("R14: 0x%x\n", regs->r14);
    PRINTF("R15: 0x%x\n\n", regs->r15);
}

static uint64_t get_xcr_supported_bits()
{
    uint64_t rax = 0xd, rcx = 0, rdx = 0, rbx = 0;
    cpuid_wrapper(&rax, &rcx, &rdx, &rbx);
    return rax;
}

static uint64_t get_extended_model_id()
{
    uint64_t rax = 0x1, rcx = 0, rdx, rbx;
    cpuid_wrapper(&rax, &rcx, &rdx, &rbx);
    return (rax >> 16) & 0xf;
}

static int is_valid_msr(uint32_t index)
{
    if ((index <= MSR_ID_LOW_MAX) ||
        (index >= MSR_ID_HIGH_MIN && index <= MSR_ID_HIGH_MAX))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

void handle_rdmsr(regs_t *regs)
{
    if (!is_valid_msr(regs->rcx))
    {
        PRINTF("Invalid MSR access: %x\n", regs->rcx);
        vmx_inject_gp(0);
        return;
    }
    uint64_t value = read_msr(regs->rcx);
    if (regs->rcx == MSR_IA32_FEATURE_CONTROL)
    {
        ia32_feature_control_register feature_control = {0};
        feature_control.all = value;
        feature_control.lock_bit = 1;
        feature_control.enable_vmx_outside_smx = 0;
        value = feature_control.all;
    }
    regs->rax = value >> 32;
    regs->rdx = value & 0xffffffff;
    vmx_advance_rip();
}

void handle_wrmsr(regs_t *regs)
{
    if (!is_valid_msr(regs->rcx))
    {
        PRINTF("Invalid MSR access: %x\n", regs->rcx);
        vmx_inject_gp(0);
        return;
    }
    uint64_t value = regs->rax << 32 | regs->rdx;
    write_msr(regs->rcx, value);
    vmx_advance_rip();
}

void handle_xsetbv(regs_t *regs)
{
    uint32_t index = regs->rcx;
    uint64_t xcr = (regs->rax & 0xffffffff) | regs->rdx << 32;

    // 检测非法的xsetbv，以防止HOST异常
    if (index != 0)
    {
        vmx_inject_gp(0);
    }

    // 无需检测cr4.xsave。未启用cr4.xsave时执行xsetbv不会被虚拟机监视器捕获，CPU自动触发UD

    uint64_t xcr_supported_bits = get_xcr_supported_bits();

    if (xcr & ~xcr_supported_bits)
    {
        vmx_inject_gp(0);
    }

    if (!(xcr & XFEATURE_MASK_FP))
    {
        vmx_inject_gp(0);
    }
    if ((xcr & XFEATURE_MASK_YMM) && !(xcr & XFEATURE_MASK_SSE))
    {
        vmx_inject_gp(0);
    }
    if ((!(xcr & XFEATURE_MASK_BNDREGS)) !=
        (!(xcr & XFEATURE_MASK_BNDCSR)))
    {
        vmx_inject_gp(0);
    }
    if (xcr & XFEATURE_MASK_AVX512)
    {
        if (!(xcr & XFEATURE_MASK_YMM))
            vmx_inject_gp(0);
        if ((xcr & XFEATURE_MASK_AVX512) != XFEATURE_MASK_AVX512)
            vmx_inject_gp(0);
    }

    if ((xcr & XFEATURE_MASK_XTILE) &&
        ((xcr & XFEATURE_MASK_XTILE) != XFEATURE_MASK_XTILE))
        vmx_inject_gp(0);

    xsetbv(index, xcr); // 直通xcr
    vmx_advance_rip();
}

void handle_init(regs_t *regs)
{
    uint64_t extended_model_id = get_extended_model_id();
    regs->rax = 0;
    regs->rcx = 0;
    regs->rdx = 0;
    regs->rbx = 0x600 | (extended_model_id << 16);
    regs->rbp = 0;
    regs->rsi = 0;
    regs->rdi = 0;
    regs->r8 = 0;
    regs->r9 = 0;
    regs->r10 = 0;
    regs->r11 = 0;
    regs->r12 = 0;
    regs->r13 = 0;
    regs->r14 = 0;
    regs->r15 = 0;

    write_cr2(0);
    write_dr0(0);
    write_dr1(0);
    write_dr2(0);
    write_dr3(0);
    write_dr6(0xffff0ff0);

    uint64_t cr0 = vmread(GUEST_CR0);
    cr0 &= CR0_CD_MASK | CR0_NW_MASK;
    cr0 |= CR0_ET_MASK;
    cr0 = vmx_ajust_cr0(cr0);
    cr0 &= ~CR0_PE_MASK;
    cr0 &= ~CR0_PG_MASK;
    vmwrite(GUEST_CR0, cr0);
    vmwrite(CR0_READ_SHADOW, cr0);

    uint64_t cr4 = vmx_ajust_cr4(0);
    vmwrite(GUEST_CR4, cr4);
    vmwrite(CR4_READ_SHADOW, cr4 & ~CR4_VMXE_MASK);

    vmwrite(GUEST_CR3, 0);
    vmwrite(GUEST_DR7, 0x400);
    vmwrite(GUEST_IA32_EFER, 0);

    vmx_segment_ar_t code_ar = {0}, data_ar = {0}, ldtr_ar = {0}, task_ar = {0};

    code_ar.present = data_ar.present = ldtr_ar.present = task_ar.present = 1;
    code_ar.descriptor_type = data_ar.descriptor_type = 1;

    code_ar.segment_type = SEGMENT_CODE_RX_ACCESSED;
    data_ar.segment_type = SEGMENT_DATA_RW_ACCESSED;
    ldtr_ar.segment_type = SEGMENT_SYSTEM_LDT;
    task_ar.segment_type = SEGMENT_SYSTEM_32BIT_TSS_BUSY;

    vmwrite(GUEST_CS_SELECTOR, 0xf000);
    vmwrite(GUEST_CS_BASE, 0xffff0000);
    vmwrite(GUEST_CS_LIMIT, 0xffff);
    vmwrite(GUEST_CS_AR_BYTES, code_ar.all);
    vmwrite(GUEST_SS_SELECTOR, 0);
    vmwrite(GUEST_SS_BASE, 0);
    vmwrite(GUEST_SS_LIMIT, 0xffff);
    vmwrite(GUEST_SS_AR_BYTES, data_ar.all);
    vmwrite(GUEST_DS_SELECTOR, 0);
    vmwrite(GUEST_DS_BASE, 0);
    vmwrite(GUEST_DS_LIMIT, 0xffff);
    vmwrite(GUEST_DS_AR_BYTES, data_ar.all);
    vmwrite(GUEST_ES_SELECTOR, 0);
    vmwrite(GUEST_ES_BASE, 0);
    vmwrite(GUEST_ES_LIMIT, 0xffff);
    vmwrite(GUEST_ES_AR_BYTES, data_ar.all);
    vmwrite(GUEST_FS_SELECTOR, 0);
    vmwrite(GUEST_FS_BASE, 0);
    vmwrite(GUEST_FS_LIMIT, 0xffff);
    vmwrite(GUEST_FS_AR_BYTES, data_ar.all);
    vmwrite(GUEST_GS_SELECTOR, 0);
    vmwrite(GUEST_GS_BASE, 0);
    vmwrite(GUEST_GS_LIMIT, 0xffff);
    vmwrite(GUEST_GS_AR_BYTES, data_ar.all);
    vmwrite(GUEST_TR_SELECTOR, 0);
    vmwrite(GUEST_TR_BASE, 0);
    vmwrite(GUEST_TR_LIMIT, 0xffff);
    vmwrite(GUEST_TR_AR_BYTES, task_ar.all);
    vmwrite(GUEST_LDTR_SELECTOR, 0);
    vmwrite(GUEST_LDTR_BASE, 0);
    vmwrite(GUEST_LDTR_LIMIT, 0xffff);
    vmwrite(GUEST_LDTR_AR_BYTES, ldtr_ar.all);

    vmwrite(GUEST_GDTR_BASE, 0);
    vmwrite(GUEST_GDTR_LIMIT, 0xffff);
    vmwrite(GUEST_IDTR_BASE, 0);
    vmwrite(GUEST_IDTR_LIMIT, 0xffff);

    vmwrite(GUEST_RFLAGS, 2);
    vmwrite(GUEST_RIP, 0xfff0);
    vmwrite(GUEST_RSP, 0);

    vmx_guest_exit_ia32e(); // 退出IA32E

    invvpid_single(vmread(VIRTUAL_PROCESSOR_ID));

    vmwrite(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_WAIT_SIPI);
}

void handle_sipi()
{
    uint64_t vector = vmread(EXIT_QUALIFICATION);
    vmwrite(GUEST_CS_SELECTOR, vector << 8);
    vmwrite(GUEST_CS_BASE, vector << 12);
    vmwrite(GUEST_RIP, 0);
    vmwrite(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
}
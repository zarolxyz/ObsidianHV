#include <stdint.h>
#include "intrin.h"
#include "hvos.h"
#include "basic_lib.h"

uint64_t get_divide_error_handler();
uint64_t get_debug_handler();
uint64_t get_nmi_handler();
uint64_t get_breakpoint_handler();
uint64_t get_overflow_handler();
uint64_t get_bound_range_exceeded_handler();
uint64_t get_invalid_opcode_handler();
uint64_t get_device_not_available_handler();
uint64_t get_double_fault_handler();
uint64_t get_coprocessor_segment_overrun_handler();
uint64_t get_invalid_tss_handler();
uint64_t get_segment_not_present_handler();
uint64_t get_stack_segment_fault_handler();
uint64_t get_general_protection_handler();
uint64_t get_page_fault_handler();
uint64_t get_x87_floating_point_error_handler();
uint64_t get_alignment_check_handler();
uint64_t get_machine_check_handler();
uint64_t get_simd_floating_point_error_handler();
uint64_t get_virtualization_exception_handler();
uint64_t get_control_protection_handler();

static void build_task_desc(segment_desc64_t *desc, uint64_t tss_base)
{
    desc->segment_limit_low = 0x67;
    desc->base_address_low = tss_base & 0xFFFF;
    desc->base_address_middle = (tss_base >> 16) & 0xFF;
    desc->base_address_high = (tss_base >> 24) & 0xFF;
    desc->base_address_upper = (tss_base >> 32) & 0xFFFFFFFF;
    desc->type = 0x9;
    desc->descriptor_type = 0;
    desc->descriptor_privilege_level = 0;
    desc->present = 1;
    desc->segment_limit_high = 0;
    desc->available_bit = 0;
    desc->long_mode = 0;
    desc->default_big = 0;
    desc->granularity = 0;
    desc->must_be_zero = 0;
}

// 构造x86_64代码段描述符
static void build_code_desc(segment_desc_t *desc)
{
    desc->segment_limit_low = 0xFFFF;
    desc->base_address_low = 0;
    desc->base_address_middle = 0;
    desc->type = 0xA; // 可执行，非一致，向上扩展
    desc->descriptor_type = 1;
    desc->descriptor_privilege_level = 0;
    desc->present = 1;
    desc->segment_limit_high = 0xF;
    desc->available_bit = 0;
    desc->long_mode = 1;
    desc->default_big = 0;
    desc->granularity = 1;
    desc->base_address_high = 0;
}

static void init_gdt(hvos_gdt_t *gdt, tss_t *tss)
{
    gdt->null = (segment_desc_t){0};
    build_code_desc(&gdt->code);
    build_task_desc(&gdt->task, (uint64_t)tss);
}

static void set_idt_entry(gate_desc_t *idt, uint8_t vector, uint16_t selector, uint64_t handler_addr)
{
    gate_desc_t *entry = &idt[vector];
    entry->offset_low = handler_addr & 0xFFFF;
    entry->segment_selector = selector;
    entry->interrupt_stack_table = 0;
    entry->must_be_zero_0 = 0;
    entry->type = 0xE;
    entry->must_be_zero_1 = 0;
    entry->descriptor_privilege_level = 0;
    entry->present = 1;
    entry->offset_middle = (handler_addr >> 16) & 0xFFFF;
    entry->offset_high = (handler_addr >> 32) & 0xFFFFFFFF;
    entry->reserved = 0;
}

static void init_hvos_idt(hvos_idt_t *idt)
{
    zero_mem(idt, sizeof(hvos_idt_t));
    set_idt_entry(idt->gates, DIVIDE_ERROR, HV_CS, (uint64_t)get_divide_error_handler());
    set_idt_entry(idt->gates, DEBUG, HV_CS, (uint64_t)get_debug_handler());
    set_idt_entry(idt->gates, NMI, HV_CS, (uint64_t)get_nmi_handler());
    set_idt_entry(idt->gates, BREAKPOINT, HV_CS, (uint64_t)get_breakpoint_handler());
    set_idt_entry(idt->gates, OVERFLOW, HV_CS, (uint64_t)get_overflow_handler());
    set_idt_entry(idt->gates, BOUND_RANGE_EXCEEDED, HV_CS, (uint64_t)get_bound_range_exceeded_handler());
    set_idt_entry(idt->gates, INVALID_OPCODE, HV_CS, (uint64_t)get_invalid_opcode_handler());
    set_idt_entry(idt->gates, DEVICE_NOT_AVAILABLE, HV_CS, (uint64_t)get_device_not_available_handler());
    set_idt_entry(idt->gates, DOUBLE_FAULT, HV_CS, (uint64_t)get_double_fault_handler());
    set_idt_entry(idt->gates, COPROCESSOR_SEGMENT_OVERRUN, HV_CS, (uint64_t)get_coprocessor_segment_overrun_handler());
    set_idt_entry(idt->gates, INVALID_TSS, HV_CS, (uint64_t)get_invalid_tss_handler());
    set_idt_entry(idt->gates, SEGMENT_NOT_PRESENT, HV_CS, (uint64_t)get_segment_not_present_handler());
    set_idt_entry(idt->gates, STACK_SEGMENT_FAULT, HV_CS, (uint64_t)get_stack_segment_fault_handler());
    set_idt_entry(idt->gates, GENERAL_PROTECTION, HV_CS, (uint64_t)get_general_protection_handler());
    set_idt_entry(idt->gates, PAGE_FAULT, HV_CS, (uint64_t)get_page_fault_handler());
    set_idt_entry(idt->gates, X87_FLOATING_POINT_ERROR, HV_CS, (uint64_t)get_x87_floating_point_error_handler());
    set_idt_entry(idt->gates, ALIGNMENT_CHECK, HV_CS, (uint64_t)get_alignment_check_handler());
    set_idt_entry(idt->gates, MACHINE_CHECK, HV_CS, (uint64_t)get_machine_check_handler());
    set_idt_entry(idt->gates, SIMD_FLOATING_POINT_ERROR, HV_CS, (uint64_t)get_simd_floating_point_error_handler());
    set_idt_entry(idt->gates, VIRTUALIZATION_EXCEPTION, HV_CS, (uint64_t)get_virtualization_exception_handler());
    set_idt_entry(idt->gates, CONTROL_PROTECTION, HV_CS, (uint64_t)get_control_protection_handler());
}

static int check_pdpe1gb()
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

static void build_identity_pdpt(pdpte_t *pdpt)
{
    zero_mem(pdpt, sizeof(pdpte_t) * 512);
    for (int i = 0; i < 512; i++)
    {
        pdpt[i].large = (large_pdpte_t){
            .present = 1,
            .write = 1,
            .large_page = 1,
            .page_frame_number = i,
        };
    }
}

static void init_hvos_pt(hvos_pt_t *pt)
{
    zero_mem(pt, sizeof(hvos_pt_t));
    build_identity_pdpt(pt->pdpt);
    pt->pml4[0] = (pml4e_t){
        .present = 1,
        .write = 1,
        .page_frame_number = (uint64_t)pt->pdpt >> PAGE_SHIFT,
    };
}

void handle_divide_error(void)
{
    PRINTF("Exception code: Divide Error\n");
    PANIC();
}

void handle_debug(void)
{
    PRINTF("Exception code: Debug\n");
    PANIC();
}

void handle_nmi(void)
{
    PRINTF("Exception code: NMI\n");
    PANIC();
}

void handle_breakpoint(void)
{
    PRINTF("Exception code: Breakpoint\n");
    PANIC();
}

void handle_overflow(void)
{
    PRINTF("Exception code: Overflow\n");
    PANIC();
}

void handle_bound_range_exceeded(void)
{
    PRINTF("Exception code: Bound Range Exceeded\n");
    PANIC();
}

void handle_invalid_opcode(void)
{
    PRINTF("Exception code: Invalid Opcode\n");
    PANIC();
}

void handle_device_not_available(void)
{
    PRINTF("Exception code: Device Not Available\n");
    PANIC();
}

void handle_double_fault(void)
{
    PRINTF("Exception code: Double Fault\n");
    PANIC();
}

void handle_coprocessor_segment_overrun(void)
{
    PRINTF("Exception code: Coprocessor Segment Overrun\n");
    PANIC();
}

void handle_invalid_tss(void)
{
    PRINTF("Exception code: Invalid TSS\n");
    PANIC();
}

void handle_segment_not_present(void)
{
    PRINTF("Exception code: Segment Not Present\n");
    PANIC();
}

void handle_stack_segment_fault(void)
{
    PRINTF("Exception code: Stack Segment Fault\n");
    PANIC();
}

void handle_general_protection(void)
{
    PRINTF("Exception code: General Protection\n");
    PANIC();
}

void handle_page_fault(void)
{
    PRINTF("Exception code: Page Fault\n");
    PANIC();
}

void handle_x87_floating_point_error(void)
{
    PRINTF("Exception code: X87 Floating Point Error\n");
    PANIC();
}

void handle_alignment_check(void)
{
    PRINTF("Exception code: Alignment Check\n");
    PANIC();
}

void handle_machine_check(void)
{
    PRINTF("Exception code: Machine Check\n");
    PANIC();
}

void handle_simd_floating_point_error(void)
{
    PRINTF("Exception code: SIMD Floating Point Error\n");
    PANIC();
}

void handle_virtualization_exception(void)
{
    PRINTF("Exception code: Virtualization Exception\n");
    PANIC();
}

void handle_control_protection(void)
{
    PRINTF("Exception code: Control Protection\n");
    PANIC();
}

int init_hvos_shared_data(hvos_shared_t *shared)
{
    shared->cpu_num = 0;
    if (!check_pdpe1gb())
    {
        PRINTF("CPU does not support pdpe1gb feature.\n");
        return -1;
    }
    init_hvos_pt(shared->pt);
    init_hvos_idt(shared->idt);
    return 0;
}

void init_hvos_cpu(hvos_cpu_t *cpu, hvos_shared_t *shared)
{
    cpu->cpu_id = shared->cpu_num;
    shared->cpu_num++;
    cpu->shared = shared;
    zero_mem(cpu->tss, sizeof(tss_t));
    init_gdt(cpu->gdt, cpu->tss);
}
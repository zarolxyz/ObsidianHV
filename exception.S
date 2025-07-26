.intel_syntax noprefix

.section .text

.code64

.macro MY_PUSHAQ
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1    
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
.endm

.macro MY_POPAQ
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8    
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
.endm

.global handle_divide_error
.global handle_debug
.global handle_nmi
.global handle_breakpoint
.global handle_overflow
.global handle_bound_range_exceeded
.global handle_invalid_opcode
.global handle_device_not_available
.global handle_double_fault
.global handle_coprocessor_segment_overrun
.global handle_invalid_tss
.global handle_segment_not_present
.global handle_stack_segment_fault
.global handle_general_protection
.global handle_page_fault
.global handle_x87_floating_point_error
.global handle_alignment_check
.global handle_machine_check
.global handle_simd_floating_point_error
.global handle_virtualization_exception
.global handle_control_protection

.global get_divide_error_handler
get_divide_error_handler:
    lea rax, [rip + handle_divide_error_asm] // 动态解析以获取真实地址
    ret

.global get_debug_handler
get_debug_handler:
    lea rax, [rip + handle_debug_asm] // 动态解析以获取真实地址
    ret

.global get_nmi_handler
get_nmi_handler:
    lea rax, [rip + handle_nmi_asm] // 动态解析以获取真实地址
    ret

.global get_breakpoint_handler
get_breakpoint_handler:
    lea rax, [rip + handle_breakpoint_asm] // 动态解析以获取真实地址
    ret

.global get_overflow_handler
get_overflow_handler:
    lea rax, [rip + handle_overflow_asm] // 动态解析以获取真实地址
    ret

.global get_bound_range_exceeded_handler
get_bound_range_exceeded_handler:
    lea rax, [rip + handle_bound_range_exceeded_asm] // 动态解析以获取真实地址
    ret

.global get_invalid_opcode_handler
get_invalid_opcode_handler:
    lea rax, [rip + handle_invalid_opcode_asm] // 动态解析以获取真实地址
    ret

.global get_device_not_available_handler
get_device_not_available_handler:
    lea rax, [rip + handle_device_not_available_asm] // 动态解析以获取真实地址
    ret

.global get_double_fault_handler
get_double_fault_handler:
    lea rax, [rip + handle_double_fault_asm] // 动态解析以获取真实地址
    ret

.global get_coprocessor_segment_overrun_handler
get_coprocessor_segment_overrun_handler:
    lea rax, [rip + handle_coprocessor_segment_overrun_asm] // 动态解析以获取真实地址
    ret

.global get_invalid_tss_handler
get_invalid_tss_handler:
    lea rax, [rip + handle_invalid_tss_asm] // 动态解析以获取真实地址
    ret

.global get_segment_not_present_handler
get_segment_not_present_handler:
    lea rax, [rip + handle_segment_not_present_asm] // 动态解析以获取真实地址
    ret

.global get_stack_segment_fault_handler
get_stack_segment_fault_handler:
    lea rax, [rip + handle_stack_segment_fault_asm] // 动态解析以获取真实地址
    ret

.global get_general_protection_handler
get_general_protection_handler:
    lea rax, [rip + handle_general_protection_asm] // 动态解析以获取真实地址
    ret

.global get_page_fault_handler
get_page_fault_handler:
    lea rax, [rip + handle_page_fault_asm] // 动态解析以获取真实地址
    ret

.global get_x87_floating_point_error_handler
get_x87_floating_point_error_handler:
    lea rax, [rip + handle_x87_floating_point_error_asm] // 动态解析以获取真实地址
    ret

.global get_alignment_check_handler
get_alignment_check_handler:
    lea rax, [rip + handle_alignment_check_asm] // 动态解析以获取真实地址
    ret

.global get_machine_check_handler
get_machine_check_handler:
    lea rax, [rip + handle_machine_check_asm] // 动态解析以获取真实地址
    ret

.global get_simd_floating_point_error_handler
get_simd_floating_point_error_handler:
    lea rax, [rip + handle_simd_floating_point_error_asm] // 动态解析以获取真实地址
    ret

.global get_virtualization_exception_handler
get_virtualization_exception_handler:
    lea rax, [rip + handle_virtualization_exception_asm] // 动态解析以获取真实地址
    ret

.global get_control_protection_handler
get_control_protection_handler:
    lea rax, [rip + handle_control_protection_asm] // 动态解析以获取真实地址
    ret

.global handle_divide_error_asm
handle_divide_error_asm:
    MY_PUSHAQ
    call    handle_divide_error
    MY_POPAQ
    iretq

.global handle_debug_asm
handle_debug_asm:
    MY_PUSHAQ
    call    handle_debug
    MY_POPAQ
    iretq

.global handle_nmi_asm
handle_nmi_asm:
    MY_PUSHAQ
    call    handle_nmi
    MY_POPAQ
    iretq

.global handle_breakpoint_asm
handle_breakpoint_asm:
    MY_PUSHAQ
    call    handle_breakpoint
    MY_POPAQ
    iretq

.global handle_overflow_asm
handle_overflow_asm:
    MY_PUSHAQ
    call    handle_overflow
    MY_POPAQ
    iretq

.global handle_bound_range_exceeded_asm
handle_bound_range_exceeded_asm:
    MY_PUSHAQ
    call    handle_bound_range_exceeded
    MY_POPAQ
    iretq

.global handle_invalid_opcode_asm
handle_invalid_opcode_asm:
    MY_PUSHAQ
    call    handle_invalid_opcode
    MY_POPAQ
    iretq

.global handle_device_not_available_asm
handle_device_not_available_asm:
    MY_PUSHAQ
    call    handle_device_not_available
    MY_POPAQ
    iretq

.global handle_double_fault_asm
handle_double_fault_asm:
    MY_PUSHAQ
    call    handle_double_fault
    MY_POPAQ
    iretq

.global handle_coprocessor_segment_overrun_asm
handle_coprocessor_segment_overrun_asm:
    MY_PUSHAQ
    call    handle_coprocessor_segment_overrun
    MY_POPAQ
    iretq

.global handle_invalid_tss_asm
handle_invalid_tss_asm:
    MY_PUSHAQ
    call    handle_invalid_tss
    MY_POPAQ
    iretq

.global handle_segment_not_present_asm
handle_segment_not_present_asm:
    MY_PUSHAQ
    call    handle_segment_not_present
    MY_POPAQ
    iretq

.global handle_stack_segment_fault_asm
handle_stack_segment_fault_asm:
    MY_PUSHAQ
    call    handle_stack_segment_fault
    MY_POPAQ
    iretq

.global handle_general_protection_asm
handle_general_protection_asm:
    MY_PUSHAQ
    call    handle_general_protection
    MY_POPAQ
    iretq

.global handle_page_fault_asm
handle_page_fault_asm:
    MY_PUSHAQ
    call    handle_page_fault
    MY_POPAQ
    iretq

.global handle_x87_floating_point_error_asm
handle_x87_floating_point_error_asm:
    MY_PUSHAQ
    call    handle_x87_floating_point_error
    MY_POPAQ
    iretq

.global handle_alignment_check_asm
handle_alignment_check_asm:
    MY_PUSHAQ
    call    handle_alignment_check
    MY_POPAQ
    iretq

.global handle_machine_check_asm
handle_machine_check_asm:
    MY_PUSHAQ
    call    handle_machine_check
    MY_POPAQ
    iretq

.global handle_simd_floating_point_error_asm
handle_simd_floating_point_error_asm:
    MY_PUSHAQ
    call    handle_simd_floating_point_error
    MY_POPAQ
    iretq

.global handle_virtualization_exception_asm
handle_virtualization_exception_asm:
    MY_PUSHAQ
    call    handle_virtualization_exception
    MY_POPAQ
    iretq

.global handle_control_protection_asm
handle_control_protection_asm:
    MY_PUSHAQ
    call    handle_control_protection
    MY_POPAQ
    iretq

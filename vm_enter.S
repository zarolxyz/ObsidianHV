.intel_syntax noprefix

.section .text

.global vm_exit_handler_asm
vm_exit_handler_asm:
    // 当前rsp指向vcpu结构体

    // 这段代码用于保存当前寄存器上下文到vcpu结构体
    push rdi // 保存rdi
    mov rdi,[rsp+8] // 获取vcpu指针

    // 开始保存寄存器，顺序依照regs_t的定义
    mov [rdi + 0x00], rax
    pop rax // 原来的rdi
    mov [rdi + 0x08], rcx
    mov [rdi + 0x10], rdx
    mov [rdi + 0x18], rbx
    mov [rdi + 0x20], rbp
    mov [rdi + 0x28], rsi
    mov [rdi + 0x30], rax // 原来的rdi
    mov [rdi + 0x38], r8
    mov [rdi + 0x40], r9
    mov [rdi + 0x48], r10
    mov [rdi + 0x50], r11
    mov [rdi + 0x58], r12
    mov [rdi + 0x60], r13
    mov [rdi + 0x68], r14
    mov [rdi + 0x70], r15

    sub rsp, 0x28
    call vm_exit_handler // 调用C函数处理，此时rdi指向vcpu结构体，作为参数传递
    add rsp, 0x28

    mov rdi, [rsp] // 获取vcpu指针

    // 恢复寄存器
    mov rax, [rdi + 0x00]
    mov rcx, [rdi + 0x08]
    mov rdx, [rdi + 0x10]
    mov rbx, [rdi + 0x18]
    mov rbp, [rdi + 0x20]
    mov rsi, [rdi + 0x28]
    // mov rdi, [rdi + 0x30]
    mov r8, [rdi + 0x38]
    mov r9, [rdi + 0x40]
    mov r10, [rdi + 0x48]
    mov r11, [rdi + 0x50]
    mov r12, [rdi + 0x58]
    mov r13, [rdi + 0x60]
    mov r14, [rdi + 0x68]
    mov r15, [rdi + 0x70]
    mov rdi, [rdi + 0x30]

    vmresume // 返回guest，继续执行

.global get_vm_exit_handler_asm
get_vm_exit_handler_asm:
    lea rax, [rip + vm_exit_handler_asm] // 动态解析以获取真实地址
    ret

.global capture_guest_regs // 捕获guest寄存器，即调用者的寄存器上下文，VMLAUNCH时，CPU从调用此函数的后面一条指令开始执行
capture_guest_regs:
    mov rax, [rsp] // 获取返回地址
    mov [rdi + 0x78], rax // 保存返回地址到rip
    // 保存返回后的栈指针
    mov rax, rsp
    add rax, 8 // 调整栈指针以跳过返回地址
    mov [rdi + 0x80], rax // 保存rsp

    mov rax, 1 // 标记为已执行过VMLAUNCH
    // 按照regs_t的定义保存寄存器
    mov [rdi + 0x00], rax
    mov [rdi + 0x08], rcx
    mov [rdi + 0x10], rdx
    mov [rdi + 0x18], rbx
    mov [rdi + 0x20], rbp
    mov [rdi + 0x28], rsi
    // mov [rdi + 0x30], rdi
    mov [rdi + 0x38], r8
    mov [rdi + 0x40], r9
    mov [rdi + 0x48], r10
    mov [rdi + 0x50], r11
    mov [rdi + 0x58], r12
    mov [rdi + 0x60], r13
    mov [rdi + 0x68], r14
    mov [rdi + 0x70], r15

    xor rax, rax // 清零rax, 标记为未执行过VMLAUNCH
    ret

.global launch_vcpu_asm
launch_vcpu_asm:

    // 保存当前寄存器，用于VMLAUNCH失败的情况
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rbp
    push rbx
    push rdx
    push rcx
    push rax

    // 提取guest寄存器
    mov rax, [rdi]
    mov rcx, [rdi+8]
    mov rdx, [rdi+16]
    mov rbx, [rdi+24]
    mov rbp, [rdi+32]
    mov rsi, [rdi+40]
    mov r8,  [rdi+56]
    mov r9,  [rdi+64]
    mov r10, [rdi+72]
    mov r11, [rdi+80]
    mov r12, [rdi+88]
    mov r13, [rdi+96]
    mov r14, [rdi+104]
    mov r15, [rdi+112]
    mov rdi, [rdi+48]
    vmlaunch

    // 恢复寄存器
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    ret
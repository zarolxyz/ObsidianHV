.intel_syntax noprefix

.section .text

.global failed
failed:
    mov eax, 1          // 设置返回值为1，表示VMX操作失败
    ret

// 进入VMX操作模式
.globl vmxon
vmxon:
    vmxon [rdi]           // RDI=VMXON区域物理地址指针
    jc failed  // 如果CF=1, 则表示VMXON失败
    xor eax, eax         // 清除EAX
    ret

// 清除VMCS状态
.globl vmclear
vmclear:
    vmclear [rdi]         // RDI=VMCS区域物理地址指针
    jc failed             // 如果CF=1, 则表示VMCS清除失败
    xor eax, eax         // 清除EAX
    ret

// 加载当前VMCS指针
.globl vmptrld
vmptrld:
    vmptrld [rdi]         // RDI=VMCS物理地址指针
    jc failed             // 如果CF=1, 则表示VMCS加载失败
    xor eax, eax         // 清除EAX
    ret

// 存储当前VMCS指针
.globl vmptrst
vmptrst:
    vmptrst [rdi]         // RDI=存储VMCS指针的内存地址
    jc failed             // 如果CF=1, 则表示VMCS存储失败
    xor eax, eax         // 清除EAX
    ret

// 从VMCS读取字段
.globl vmread
vmread:
    vmread rax,rdi       // RSI=读取结果存储地址
    jc failed             // 如果CF=1, 则表示VMREAD失败
    jz failed          // 如果ZF=1, 则表示VMCS无效
    // 如果成功，结果存储在RSI中
    mov [rsi], rax         // 将读取结果存储到RSI
    xor eax, eax         // 清除EAX
    ret

// 写入VMCS字段
.globl vmwrite
vmwrite:
    vmwrite rdi, rsi
    jc failed             // 如果CF=1, 则表示VMWRITE失败
    jz failed          // 如果ZF=1, 则表示VMCS无效
    xor eax, eax         // 清除EAX
    ret

// 启动虚拟机
.globl vmlaunch
vmlaunch:
    vmlaunch             // 无参数，成功时不会返回
    ret

// 恢复虚拟机
.globl vmresume
vmresume:
    vmresume             // 无参数，成功时不会返回
    ret

// 退出VMX操作模式
.globl vmxoff
vmxoff:
    vmxoff               // 无参数
    jc failed  // 如果CF=1, 则表示VMXOFF失败
    xor eax, eax         // 清除EAX
    ret

/*

typedef struct
{
  vcpu_t *vcpu;
  ...
} vmx_cpu_t;

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
  ...
} vcpu_t;

*/

.global vmx_exit_handler_asm
vmx_exit_handler_asm:
    // 当前rsp指向vmx_cpu结构体

    // 这段代码用于保存当前寄存器上下文到vcpu结构体
    push rdi // 保存rdi，用来存储vcpu指针
    mov rdi,[rsp+8] // 获取vmx_cpu指针
    mov rdi,[rdi] // 获取vcpu指针

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

    mov rdi, [rsp] // 获取vmx_cpu指针
    sub rsp, 0x28
    call vmx_exit_handler
    add rsp, 0x28

    mov rdi, [rsp] // 获取vmx_cpu指针
    mov rdi, [rdi] // 获取vcpu指针

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

    vmresume

.global vmx_get_exit_handler
vmx_get_exit_handler:
    lea rax, [rip + vmx_exit_handler_asm] // 动态解析以获取真实地址
    ret

.global vmx_capture
vmx_capture:
    mov rdi, [rdi] // 获取vcpu指针

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

.global vmx_launch
vmx_launch:
    mov rdi, [rdi] // 获取vcpu指针

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
    cli
    vmlaunch
    sti

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

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
    vmread rax,rdi
    ret

// 写入VMCS字段
.globl vmwrite
vmwrite:
    vmwrite rdi, rsi
    ret

// 退出VMX操作模式
.globl vmxoff
vmxoff:
    vmxoff               // 无参数
    jc failed  // 如果CF=1, 则表示VMXOFF失败
    xor eax, eax         // 清除EAX
    ret

.global invvpid
invvpid:
    mov     rcx, rsi         # 将描述符指针存入RCX (INVVPID要求)
    mov     rax, rdi         # 指令类型存入RAX
    invvpid rax, oword ptr [rcx]
    ret

.global invept
invept:
    mov     rcx, rsi         # 描述符指针 -> RCX
    mov     rax, rdi         # 指令类型 -> RAX
    invept  rax, oword ptr [rcx]  # 执行指令
    ret
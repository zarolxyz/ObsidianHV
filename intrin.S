.intel_syntax noprefix        # 使用Intel语法

/* 控制寄存器 (CR0, CR2, CR3, CR4) */
.global read_cr0
read_cr0:
    mov rax, cr0
    ret

.global write_cr0
write_cr0:
    mov cr0, rdi              # 参数通过RDI传递
    ret

.global read_cr2
read_cr2:
    mov rax, cr2              # 缺页地址寄存器
    ret

.global read_cr3
read_cr3:
    mov rax, cr3              # 页目录基址寄存器
    ret

.global write_cr3
write_cr3:
    mov cr3, rdi
    ret

.global read_cr4
read_cr4:
    mov rax, cr4
    ret

.global write_cr4
write_cr4:
    mov cr4, rdi
    ret

/* GDTR/IDTR操作 */
.global read_gdtr
read_gdtr:
    sgdt [rdi]                # 将GDTR内容存入RDI指向的内存（10字节）
    ret

.global write_gdtr
write_gdtr:
    lgdt [rdi]                # 从RDI指向的内存加载GDTR
    ret

.global read_idtr
read_idtr:
    sidt [rdi]                # 将IDTR内容存入RDI指向的内存
    ret

.global write_idtr
write_idtr:
    lidt [rdi]                # 从RDI指向的内存加载IDTR
    ret

.global read_msr
/* MSR操作 */
read_msr:
    // 输入: edi = MSR索引号 (32位)
    mov ecx, edi         // 将索引存入ecx (RDMSR要求)
    rdmsr                // 结果高32位在edx，低32位在eax
    shl rdx, 32          // 将edx左移32位
    or  rax, rdx         // 合并edx和eax到rax (64位返回值)
    ret

.global write_msr
write_msr:
    // 输入: edi = MSR索引号, rsi = 64位值
    mov ecx, edi         // 索引存入ecx
    mov eax, esi         // 取value的低32位到eax
    mov rdx, rsi         // 复制value到rdx
    shr rdx, 32          // 取value的高32位到edx (RDX高32位自动清零)
    wrmsr                // 执行写入 (edx:eax -> ecx指定的MSR)
    ret

.global read_cs
read_cs:
    mov ax, cs
    ret

.global read_ds
read_ds:
    mov ax, ds
    ret

.global read_es
read_es:
    mov ax, es
    ret

.global read_fs
read_fs:
    mov ax, fs
    ret

.global read_gs
read_gs:
    mov ax, gs
    ret

.global read_ss
read_ss:
    mov ax, ss
    ret

.global read_tr
read_tr:
    str ax
    ret

// CS访问权限
.global read_cs_access_rights
read_cs_access_rights:
    mov ax,  cs                // 读取CS段选择符到AX
    lar rax, ax           // 使用LAR指令获取CS的访问权限
    ret
// DS访问权限
.global read_ds_access_rights
read_ds_access_rights:
    mov ax,  ds                // 读取DS段选择符到AX
    lar rax, ax           // 使用LAR指令获取DS的访问权限
    ret
// ES访问权限
.global read_es_access_rights
read_es_access_rights:
    mov ax,  es                // 读取ES段选择符到AX
    lar rax, ax           // 使用LAR指令获取ES的访问权限
    ret
// FS访问权限
.global read_fs_access_rights
read_fs_access_rights:
    mov ax,  fs                // 读取FS段选择符到AX
    lar rax, ax           // 使用LAR指令获取FS的访问权限
    ret
// GS访问权限
.global read_gs_access_rights
read_gs_access_rights:
    mov ax,  gs                // 读取GS段选择符到AX
    lar rax, ax           // 使用LAR指令获取GS的访问权限
    ret
// SS访问权限
.global read_ss_access_rights
read_ss_access_rights:
    mov ax,  ss                // 读取SS段选择符到AX
    lar rax, ax           // 使用LAR指令获取SS的访问权限
    ret

// 使用LAR指令读取TSS访问权限
.global read_tr_access_rights
read_tr_access_rights:
    str ax                // 读取TSS段选择符到AX
    lar rax, ax           // 使用LAR指令获取TSS的访问权限
    ret

// dr寄存器操作
.global read_dr0
read_dr0:
    mov rax, dr0
    ret
    
.global read_dr1
read_dr1:
    mov rax, dr1
    ret

.global read_dr2
read_dr2:
    mov rax, dr2
    ret

.global read_dr3
read_dr3:
    mov rax, dr3
    ret

.global read_dr6
read_dr6:
    mov rax, dr6
    ret

.global read_dr7
read_dr7:
    mov rax, dr7
    ret

.global write_dr0
write_dr0:
    mov dr0, rdi              // 参数通过RDI传递
    ret

.global write_dr1
write_dr1:
    mov dr1, rdi              // 参数通过RDI传递
    ret

.global write_dr2
write_dr2:
    mov dr2, rdi              // 参数通过RDI传递
    ret

.global write_dr3
write_dr3:
    mov dr3, rdi              // 参数通过RDI传递
    ret

.global write_dr6
write_dr6:
    mov dr6, rdi              // 参数通过RDI传递
    ret

.global write_dr7
write_dr7:
    mov dr7, rdi              // 参数通过RDI传递
    ret

// 读取rflags寄存器
.global read_rflags
read_rflags:
    pushfq                // 将EFLAGS压入栈
    pop rax              // 弹出到RAX
    ret

// void out_byte(uint16_t port, uint8_t value);
.global out_byte
out_byte:
    mov rdx, rdi              // 参数通过RDI传递
    mov rax, rsi              // 参数通过RSI传递
    out dx, al
    ret

// uint8_t in_byte(uint16_t port);
.global in_byte
in_byte:
    mov rdx, rdi              // 参数通过RDI传递
    in al, dx
    ret

// void wbinvd_wrapper(void);
.global wbinvd_wrapper
wbinvd_wrapper:
    wbinvd
    ret

// void disable_interrupt(void);
.global disable_interrupt
disable_interrupt:
    cli
    ret

// void cpuid_wrapper(uint64_t *rax, uint64_t *rcx, uint64_t *rdx, uint64_t *rbx);
.global cpuid_wrapper
#   rdi = eax_ptr (输入主功能号，输出EAX结果)
#   rsi = ecx_ptr (输入子功能号，输出ECX结果)
#   rdx = edx_ptr (输出EDX结果)
#   rcx = ebx_ptr (输出EBX结果)
cpuid_wrapper:
    push rbx                 # 保存被调用者保存的寄存器（RBX会被CPUID修改）[1,5](@ref)
    mov r8, rdx              # 保存第三个参数（edx_ptr）到临时寄存器R8
    mov r9, rcx              # 保存第四个参数（ebx_ptr）到临时寄存器R9

    # 加载输入参数到寄存器
    mov rax, [rdi]           # 从eax_ptr加载主功能号到EAX[1,9](@ref)
    mov rcx, [rsi]           # 从ecx_ptr加载子功能号到ECX[1,9](@ref)

    cpuid                    # 执行CPUID指令（结果存入EAX/EBX/ECX/EDX）[1,2](@ref)

    # 将结果存储到指针指向的内存
    mov [rdi], rax           # 存储EAX结果到eax_ptr[1,9](@ref)
    mov [rsi], rcx           # 存储ECX结果到ecx_ptr[1,9](@ref)
    mov [r8], rdx            # 存储EDX结果到edx_ptr（通过临时寄存器R8）[1,9](@ref)
    mov [r9], rbx            # 存储EBX结果到ebx_ptr（通过临时寄存器R9）[1,9](@ref)

    pop rbx                  # 恢复原始RBX值[1,5](@ref)
    ret                      # 返回调用者

.global xsetbv_wrapper
#   rdi = ecx (输入ECX)
#   rsi = eax (输入EAX)
#   rdx = edx (输入EDX)
xsetbv_wrapper:
    mov rcx, rdi              # 保存第一个参数（ecx）到ECX[1,9](@ref)
    mov rax, rsi              # 保存第二个参数（eax）到EAX[1,9](@ref)
    xsetbv                    # 执行xsetbv指令（结果存入EAX/ECX/EDX）[1,2](@ref)
    ret

.global read_tsc
read_tsc:
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret
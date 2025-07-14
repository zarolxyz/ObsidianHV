#pragma once
#include <stdint.h>

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

void xsetbv_wrapper(uint64_t rcx, uint64_t rax, uint64_t rdx);

uint64_t read_tsc(void);
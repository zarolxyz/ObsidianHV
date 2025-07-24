#include "vmx.h"
#include "intrin.h"
#include "basic_lib.h"
#include "ia32.h"

#define INVEPT_SINGLE_CONTEXT 0x00000001
#define INVEPT_ALL_CONTEXT 0x00000002

#define INVVPID_INDIVIDUAL_ADDRESS 0x00000000
#define INVVPID_SINGLE_CONTEXT 0x00000001
#define INVVPID_ALL_CONTEXT 0x00000002
#define INVVPID_SINGLE_CONTEXT_RETAINING_GLOBALS 0x00000003

typedef struct
{
  uint64_t ept_pointer;
  uint64_t reserved;
} invept_descriptor_t;

typedef struct
{
  uint16_t vpid;
  uint16_t reserved1;
  uint32_t reserved2;
  uint64_t linear_address;
} invvpid_descriptor_t;

void invept(int type, const invept_descriptor_t *desc);
void invvpid(int type, const invvpid_descriptor_t *desc);
void invvpid_single(uint16_t vpid)
{
  invvpid_descriptor_t desc = {.vpid = vpid};
  invvpid(INVVPID_SINGLE_CONTEXT, &desc);
}

void invept_single(uint64_t eptp)
{
  invept_descriptor_t desc = {.ept_pointer = eptp};
  invept(INVEPT_SINGLE_CONTEXT, &desc);
}

// 判断CPU是否支持VMX虚拟化
int vmx_check_cpuid()
{
  uint64_t rax = 0x1, rbx, rcx = 0, rdx;
  cpuid_wrapper(&rax, &rcx, &rdx, &rbx);

  const uint8_t VMX_BIT = 5; // ECX寄存器的第5位表示VMX支持[6,8](@ref)
  return (rcx >> VMX_BIT) & 1;
}

int vmx_check_feature_control()
{
  ia32_feature_control_register feature_control;
  feature_control.all = read_msr(MSR_IA32_FEATURE_CONTROL);
  if (feature_control.enable_vmx_outside_smx)
  {
    return 1;
  }
  return 0;
}

uint64_t vmx_ajust_cr0(uint64_t value)
{
  value &= read_msr(MSR_IA32_VMX_CR0_FIXED1);
  value |= read_msr(MSR_IA32_VMX_CR0_FIXED0);
  return value;
}

uint64_t vmx_ajust_cr4(uint64_t value)
{
  value &= read_msr(MSR_IA32_VMX_CR4_FIXED1);
  value |= read_msr(MSR_IA32_VMX_CR4_FIXED0);
  return value;
}

void msr_bitmap_set_read(msr_bitmap_t *msr_bitmap, uint32_t index)
{
  if (index >= MSR_ID_HIGH_MIN)
  {
    // 计算高位MSR相对基址的偏移量
    uint32_t offset = index - MSR_ID_HIGH_MIN;
    bitmap_set_bit(msr_bitmap->read_high, offset);
  }
  else
  {
    bitmap_set_bit(msr_bitmap->read_low, index);
  }
}

void msr_bitmap_set_write(msr_bitmap_t *msr_bitmap, uint32_t index)
{
  if (index >= MSR_ID_HIGH_MIN)
  {
    // 计算高位MSR相对基址的偏移量
    uint32_t offset = index - MSR_ID_HIGH_MIN;
    bitmap_set_bit(msr_bitmap->write_high, offset);
  }
  else
  {
    bitmap_set_bit(msr_bitmap->write_low, index);
  }
}

void init_msr_bitmap(msr_bitmap_t *msr_bitmap)
{
  zero_mem(msr_bitmap, sizeof(msr_bitmap_t));
}

uint32_t vmx_adjust_control_value(uint32_t msr_index,
                                  uint32_t control_value)
{
  uint64_t msr_value = read_msr(msr_index);
  uint32_t msr_high = msr_value >> 32;
  uint32_t msr_low = msr_value & 0xFFFFFFFF;
  return (control_value | msr_low) & msr_high;
}

void vmx_set_control_field(uint32_t field, uint64_t control)
{
  uint32_t msr_index = 0;
  switch (field)
  {
  case VM_ENTRY_CONTROLS:
    msr_index = MSR_IA32_VMX_TRUE_ENTRY_CTLS;
    break;
  case VM_EXIT_CONTROLS:
    msr_index = MSR_IA32_VMX_TRUE_EXIT_CTLS;
    break;
  case PIN_BASED_VM_EXEC_CONTROL:
    msr_index = MSR_IA32_VMX_TRUE_PINBASED_CTLS;
    break;
  case CPU_BASED_VM_EXEC_CONTROL:
    msr_index = MSR_IA32_VMX_TRUE_PROCBASED_CTLS;
    break;
  case SECONDARY_VM_EXEC_CONTROL:
    msr_index = MSR_IA32_VMX_PROCBASED_CTLS2;
    break;
  default:
    return; // 不支持的字段
  }
  vmwrite(field, vmx_adjust_control_value(msr_index, control));
}

uint32_t vmx_convert_access_rights(uint32_t access_rights)
{
  if (access_rights == 0)
    return 0x10000;
  return (access_rights >> 8) & 0b1111000011111111;
}

void vmx_inject_interruption(int type, int vector)
{
  vm_entry_interruption_info_t info = {0};
  info.fields.valid = 1;
  info.fields.vector = vector;
  info.fields.interruption_type = type;
  info.fields.deliver_error_code = 0;
  vmwrite(VM_ENTRY_INTR_INFO_FIELD, info.all);
}

void vmx_inject_interruption_error_code(int type, int vector, uint32_t error_code)
{
  vm_entry_interruption_info_t info = {0};
  info.fields.valid = 1;
  info.fields.vector = vector;
  info.fields.interruption_type = type;
  info.fields.deliver_error_code = 1;
  vmwrite(VM_ENTRY_INTR_INFO_FIELD, info.all);
  vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
}

void vmx_advance_rip()
{
  uint64_t instruction_len = vmread(VM_EXIT_INSTRUCTION_LEN);
  uint64_t rip = vmread(GUEST_RIP);
  rip += instruction_len;
  vmwrite(GUEST_RIP, rip);
}

void vmx_inject_ud()
{
  vmx_inject_interruption(VMX_INTR_TYPE_HWEXCEPTION, INVALID_OPCODE);
}

void vmx_inject_gp(uint32_t error_code)
{
  vmx_inject_interruption_error_code(VMX_INTR_TYPE_HWEXCEPTION, GENERAL_PROTECTION, error_code);
}

// 退出GUEST IA32E模式
void vmx_guest_exit_ia32e()
{
  uint64_t entry_control = vmread(VM_ENTRY_CONTROLS);
  entry_control &= ~VM_ENTRY_IA32E_MODE;
  vmwrite(VM_ENTRY_CONTROLS, entry_control);
}

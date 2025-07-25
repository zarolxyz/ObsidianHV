#include <stdint.h>
#include "gdt.h"

void setup_task_desc(gdt_desc64_t *desc, uint64_t tss_base)
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
void setup_code_desc(gdt_desc_t *desc)
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

void build_gdt(gdt_data_t *gdt, tss64_t *tss)
{
    gdt->null = (gdt_desc_t){0};
    setup_code_desc(&gdt->code);
    setup_task_desc(&gdt->task, (uint64_t)tss);
}
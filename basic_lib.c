#include "basic_lib.h"
#include "intrin.h"
#include <stdarg.h>
#include <stdint.h>

void zero_mem(void *addr, uint64_t size)
{
  uint8_t *p = (uint8_t *)addr;
  for (uint64_t i = 0; i < size; i++)
  {
    *p = 0;
    p++;
  }
}

void copy_mem(void *target, void *source, uintptr_t size)
{
  uintptr_t i;
  for (i = 0; i < size; i++)
  {
    ((uint8_t *)target)[i] = ((uint8_t *)source)[i];
  }
}

mem_pool_t *mem_pool_create(void *pool, uintptr_t size)
{
  mem_pool_t *mem_pool = (mem_pool_t *)ALIGN_UP((uintptr_t)pool, 16);
  mem_pool->size = size;
  mem_pool->allocated_size = sizeof(mem_pool_t);
  mem_pool->pool = pool;
  return mem_pool;
}

// 分配指定对称内存块
void *mem_pool_alloc(mem_pool_t *mem_pool, uintptr_t size, uintptr_t alignment)
{
  uintptr_t base_addr = (uintptr_t)mem_pool->pool + mem_pool->allocated_size;
  uintptr_t aligned_addr = ALIGN_UP(base_addr, alignment);
  uintptr_t real_size = ALIGN_UP(aligned_addr + size, alignment) - base_addr;
  if (real_size > mem_pool->size - mem_pool->allocated_size)
    return NULL;
  mem_pool->allocated_size += real_size;
  return (void *)aligned_addr;
}

static void print_char(uint8_t value) { out_byte(DEBUG_SERIAL_PORT, value); }

const static char to_hex[] = "0123456789ABCDEF";

// 调用debug_char()输出64位 16进制数
static void print_hex(uint64_t value)
{
  for (int i = 0; i < 16; i++)
  {
    print_char(to_hex[(value >> 60) & 0xf]);
    value <<= 4;
  }
}

static void print_dec(uint64_t value)
{
  if (value >= 10)
  {
    print_dec(value / 10);
  }
  print_char(value % 10 + '0');
}

void serial_print(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  char *p_fmt = (char *)fmt;
  while (*p_fmt != 0)
  {
    if (*p_fmt == '%')
    {
      p_fmt++;
      if (*p_fmt == 'x')
      {
        print_hex(va_arg(args, uint64_t));
      }
      else if (*p_fmt == 'd')
      {
        print_dec(va_arg(args, uint64_t));
      }
    }
    else
    {
      print_char(*p_fmt);
    }
    p_fmt++;
  }
  va_end(args);
}

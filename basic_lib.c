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

int bit_scan(uint64_t value)
{
  int index = 0;
  while (value != 0)
  {
    if (value & 1)
    {
      return index;
    }
    value >>= 1;
    index++;
  }
  return -1;
}

// 从bitmap中找到第一个0的位置
uintptr_t bitmap_find_first_zero(uint8_t *bitmap, uintptr_t len)
{
  for (uintptr_t i = 0; i < len; i++)
  {
    if (bitmap_get_bit(bitmap, i) == 0)
    {
      return i;
    }
  }
  return UINTPTR_MAX;
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

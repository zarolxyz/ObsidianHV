#pragma once

#include <stdint.h>

#define PAGE_SIZE 4096
#define ALIGN_UP(val, align) (((val) + (align) - 1) & ~((align) - 1))
#define PAGE_ALIGN_UP(val) ALIGN_UP(val, PAGE_SIZE)
#define PAGE_SHIFT 12

#ifndef NULL
#define NULL ((void *)0)
#endif

void zero_mem(void *addr, uint64_t size);
void copy_mem(void *target, void *source, uintptr_t size);
int bit_scan(uint64_t value);
uintptr_t bitmap_find_first_zero(uint8_t *bitmap, uintptr_t len);

#define DEBUG_SERIAL_PORT 0x3f8
#define PRINTF(fmt, ...) serial_print(fmt, ##__VA_ARGS__)

void serial_print(const char *fmt, ...);

static inline void bitmap_set_bit(uint8_t *bits, uint32_t index)
{
  bits[index / 8] |= 1 << (index % 8);
}

static inline void bitmap_clear_bit(uint8_t *bits, uint32_t index)
{
  bits[index / 8] &= ~(1 << (index % 8));
}

static inline int bitmap_get_bit(uint8_t *bits, uint32_t index)
{
  return (bits[index / 8] >> (index % 8)) & 1;
}

#define PANIC() \
  {             \
    for (;;)    \
      ;         \
  }

#define ASSERT(expression)          \
  {                                 \
    if (!(expression))              \
    {                               \
      PRINTF("Assertion failed:"    \
             " " #expression "\n"); \
      PANIC()                       \
    }                               \
  }

#pragma once

#include <stdint.h>

#define PAGE_SIZE 4096
#define ALIGN_UP(val, align) (((val) + (align) - 1) & ~((align) - 1))
#define PAGE_ALIGN_UP(val) ALIGN_UP(val, PAGE_SIZE)

#ifndef NULL
#define NULL ((void *)0)
#endif

typedef struct
{
  uintptr_t size;
  uintptr_t allocated_size;
  void *pool;
} mem_pool_t;

void zero_mem(void *addr, uint64_t size);
mem_pool_t *mem_pool_create(void *pool, uintptr_t size);
void *mem_pool_alloc(mem_pool_t *mem_pool, uintptr_t size, uintptr_t alignment);

#define DEBUG_SERIAL_PORT 0x3f8
#define PRINTF(fmt, ...) serial_print(fmt, ##__VA_ARGS__)
// #define PRINT_DEBUG(fmt, ...) // serial_print(fmt, ##__VA_ARGS__)

void serial_print(const char *fmt, ...);

static inline void bitmap_setbit(uint8_t *bits, uint32_t index)
{
  bits[index / 8] |= 1 << (index % 8);
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

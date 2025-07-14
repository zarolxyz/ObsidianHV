#pragma once

#include <stdint.h>

typedef struct
{
    void *page_pool_base;
    int allocated_pages;
} page_pool_t;
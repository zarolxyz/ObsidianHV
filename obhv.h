#pragma once

#include "vcpu.h"
#include "ept.h"

typedef struct
{
    void *pool;
    uint64_t pool_size;
    uint64_t pool_used;
    vcpu_shared_t *vcpu_shared;
} obhv_t;

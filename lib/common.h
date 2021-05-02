#ifndef _COMMON_H
#define _COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <assert.h>
#include <string.h>

#include "libcommon/lib/util.h"
#include "libcommon/lib/perf.h"

/* Allocate uint32_t argument and sets its value */
static inline void*
alloc_void_arg_uint32_t(uint32_t value)
{
    uint32_t *arg = (uint32_t*)malloc(sizeof(uint32_t));
    *arg = value;
    return arg;
}

static inline uint32_t
get_void_arg_uint32_t(void* arg, bool del)
{
    uint32_t ret = *(uint32_t*)arg;
    if (del) {
        free(arg);
    }
    return ret;
}

static inline void*
alloc_void_arg_bytes(void *ptr, size_t size)
{
    char *arg = (char*)malloc(sizeof(char)*size);
    memcpy(arg, ptr, size);
    return arg;
}

static inline void
get_void_arg_bytes(void* dst, void* arg, size_t size, bool del)
{
    memcpy(dst, arg, size);
    if (del) {
        free(arg);
    }
}

#endif

#ifndef _COMMON_H
#define _COMMON_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>

/* Returns the address after the object pointed by POINTER casted to TYPE */
#define OBJECT_END(TYPE, POINTER) (TYPE)((char*)POINTER+sizeof(*POINTER))

/* Align to cache line */
#define CACHE_ALIGNED __attribute__ ((aligned (64)))

/* Single cache line to act as message accross cores. Access using NAME.val */
#define MESSAGE_T(TYPE, NAME) volatile static union CACHE_ALIGNED \
    { char _x[64]; TYPE val; } NAME

/* Return the time in nanosecs */
static inline uint64_t
get_time_ns()
{
    struct timespec timespec;
    uint64_t value;
    clock_gettime(CLOCK_MONOTONIC, &timespec);
    value = (timespec.tv_sec * 1e9 + timespec.tv_nsec);
    return value;
}

/* Allocate uint32_t argument and sets its value */
static inline void*
alloc_void_arg_uint32_t(uint32_t value)
{
    uint32_t *arg = (uint32_t*)malloc(sizeof(uint32_t));
    *arg = value;
    return arg;
}

static inline uint32_t
get_void_arg_uint32_t(void* arg)
{
    uint32_t ret = *(uint32_t*)arg;
    free(arg);
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
get_void_arg_bytes(void* dst, void* arg, size_t size)
{
    memcpy(dst, arg, size);
    free(arg);
}

#endif

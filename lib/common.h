#ifndef _COMMON_H
#define _COMMON_H

#include <time.h>

/* Returns the address after the object pointed by POINTER casted to TYPE */
#define OBJECT_END(TYPE, POINTER) (TYPE)((char*)POINTER+sizeof(*POINTER))

/* Align to cache line */
#define CACHE_ALIGNED __attribute__ ((aligned (64)))

/* Single cache line to act as message accross cores. Access using NAME.val */
#define MESSAGE_T(TYPE, NAME) volatile static union CACHE_ALIGNED \
    { char _x[64]; TYPE val; } NAME

/* Return the time in nanosecs */
static inline long
get_time_ns()
{
    struct timespec timespec;
    long value;
    clock_gettime(CLOCK_MONOTONIC, &timespec);
    value = (timespec.tv_sec * 1e9 + timespec.tv_nsec);
    return value;
}

#endif

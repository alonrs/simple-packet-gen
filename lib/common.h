#ifndef COMMON_H
#define COMMON_H

#include <time.h>

/* Returns the address after the object pointed by POINTER casted to TYPE */
#define OBJECT_END(TYPE, POINTER) (TYPE)((char*)POINTER+sizeof(*POINTER))

/* Align to cache line */
#define CACHE_ALIGNED __attribute__ ((aligned (64)))

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

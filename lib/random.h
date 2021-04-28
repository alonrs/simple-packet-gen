#ifndef _RANDOM_H_
#define _RANDOM_H_

#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

/* Returns a uniform number in [0.0, 1.0) */
static inline double
random_double()
{
    return drand48();
}

/* Flips a coin, returns true with probability "prob" (in 0.0-1.0) */
static inline bool
random_coin(double prob)
{
    return random_double() <= prob;
}

#endif

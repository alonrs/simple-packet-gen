#ifndef _RATE_LIMITER_H_
#define _RATE_LIMITER_H_

#include <stddef.h>
#include <stdint.h>
#include <math.h>

#include "common.h"

struct rate_limiter {
    uint64_t current_time;
    double kpps;
    uint32_t batch_size;
};

static inline void
rate_limiter_init(struct rate_limiter *rl,
                  double kpps,
                  uint32_t batch_size,
                  uint16_t num_tx_queues)
{
    rl->kpps = kpps;
    rl->current_time = get_time_ns();
    rl->batch_size = batch_size*num_tx_queues;
}

static inline void
rate_limiter_wait(struct rate_limiter *rl)
{
    double time_per_batch;
    double gap_ns;
    long current_time_ns;
    long end_time;

    if (!rl->kpps) {
        return;
    }

    /* How much it takes to run a batch? */
    current_time_ns = get_time_ns();
    time_per_batch = -rl->current_time + current_time_ns;
    gap_ns = 1e6*((double)rl->batch_size/rl->kpps) - time_per_batch;
    end_time = get_time_ns() + gap_ns;

    /* Busy-wait "gap" usec */
    do {
        current_time_ns = get_time_ns();
    } while (current_time_ns < end_time);

    rl->current_time = get_time_ns();
}

#endif

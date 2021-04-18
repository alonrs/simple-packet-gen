
#ifndef _GENERATOR_H_
#define _GENERATOR_H_

#include <stdint.h>
#include "packet.h"

/**
 * @brief Defines a function type for packet generators. Different packet
 * generators can generate packets based on difference policies.
 * @param[in] pkt_num The index of the current generated packet in the queue.
 * @param[in] queue_idx The index of the TX queue
 * @param[in] queue_total Total number of TX queues
 * @param[inout] ftuple The previous generated 5-tuple. Modified by this to
 * @param[in] args Any additional args.
 * be the next generated 5-tuple.
 */
typedef void (*generator_policy_func_t)(uint64_t pkt_num,
                                        uint16_t queue_idx,
                                        uint16_t queue_total,
                                        struct ftuple *ftuple,
                                        void *args);

/* Generates packets of a "super spreader", i.e., dest port and dest ip differ
 * for each generated 5-tuple. */
void generator_policy_superspreader(uint64_t pkt_num,
                                    uint16_t queue_idx,
                                    uint16_t queue_total,
                                    struct ftuple *ftuple,
                                    void *args);


#endif /* GIT_LIB_GENERATOR_H_ */

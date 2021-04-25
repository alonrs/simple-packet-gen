#ifndef _GENERATOR_H_
#define _GENERATOR_H_

#include <stdint.h>
#include "packet.h"

/* Generator policy */
typedef enum {
    POLICY_UNDEFINED = 0,
    POLICY_SUPERSPREADER,
    POLICY_NFLOWS,
    POLICY_PCAP
} policy_t;

/* Arguments for superspreader/nflows policies */
struct ssnf_args {
    struct ftuple base; /* Basic 5-tuple to start from */
    int flow_num;       /* Total number of flows */
};

/**
 * @brief Defines a function type for packet generators. Different packet
 * generators can generate packets based on difference policies.
 * @param[in] pkt_num The index of the current generated packet in the queue.
 * @param[in] queue_idx The index of the TX queue
 * @param[in] queue_total Total number of TX queues
 * @param[inout] ftuple The previous generated 5-tuple. Modified by this to
 * @param[in] args Any additional args.
 * be the next generated 5-tuple.
 * @returns A state that can be passed to later invocations as "args".
 */
typedef void* (*generator_policy_func_t)(uint64_t pkt_num,
                                         uint16_t queue_idx,
                                         uint16_t queue_total,
                                         struct ftuple *ftuple,
                                         void *args);

/* Generates packets of a "super spreader", i.e., dst-port and dst-ip differ
 * for each generated 5-tuple. */
void* generator_policy_superspreader(uint64_t pkt_num,
                                     uint16_t queue_idx,
                                     uint16_t queue_total,
                                     struct ftuple *ftuple,
                                     void *args);

/* Generates packets from several flows, i.e., src-ip and dst-ip differ
 * for each generated 5-tuple. */
void* generator_policy_nflows(uint64_t pkt_num,
                              uint16_t queue_idx,
                              uint16_t queue_total,
                              struct ftuple *ftuple,
                              void *args);

/* Reads packets from a PCAP file */
void* generator_policy_pcap(uint64_t pkt_num,
                            uint16_t queue_idx,
                            uint16_t queue_total,
                            struct ftuple *ftuple,
                            void *args);
#endif

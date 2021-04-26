#ifndef _GENERATOR_H_
#define _GENERATOR_H_

#include <stdint.h>
#include "packet.h"

/* The type of the generated data-structure */
typedef enum {
    GENERATOR_OUT_FTUPLE = 0,
    GENERATOR_OUT_RAW
} generator_mode_t;


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

/* Output values for raw packet */
struct raw_packet {
    const char *bytes;
    size_t size;
};

/**
 * @brief Defines a function type for packet generators. Different packet
 * generators can generate packets based on difference policies.
 * @param[in] pkt_num The index of the current generated packet in the queue.
 * @param[in] queue_idx The index of the TX queue
 * @param[in] queue_total Total number of TX queues
 * @param[in] args Any additional args.
 * @param[out] out The generated data.
 * be the next generated 5-tuple.
 * @returns A state that can be passed to later invocations as "args".
 * @note The function can set "out" as a pointer to "struct ftuple"
 * (GENERATOR_OUT_FTUPLE mode) or to "struct raw" (GENERATOR_OUT_RAW mode).
 */
typedef void* (*generator_policy_func_t)(uint64_t pkt_num,
                                         uint16_t queue_idx,
                                         uint16_t queue_total,
                                         void *args,
                                         void **out);

/* (GENERATOR_OUT_FTUPLE) Generates 5-tuples of a "super spreader",
 * i.e., dst-port and dst-ip differ for each generated 5-tuple. */
void* generator_policy_superspreader(uint64_t pkt_num,
                                     uint16_t queue_idx,
                                     uint16_t queue_total,
                                     void *args,
                                     void **out);

/* (GENERATOR_OUT_FTUPLE) Generates 5-tuples from several flows,
 * i.e., src-ip and dst-ip differ for each generated 5-tuple. */
void* generator_policy_nflows(uint64_t pkt_num,
                              uint16_t queue_idx,
                              uint16_t queue_total,
                              void *args,
                              void **out);

/* (GENERATOR_OUT_RAW) Reads packets from a PCAP file. */
void* generator_policy_pcap(uint64_t pkt_num,
                            uint16_t queue_idx,
                            uint16_t queue_total,
                            void *args,
                            void **out);
#endif

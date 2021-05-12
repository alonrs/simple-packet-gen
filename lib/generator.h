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
    POLICY_PATHS,
    POLICY_PCAP
} policy_t;

/* Policy knobs set by command line, filled by in "main.c" */
struct policy_knobs {
    double n1;
    double n2;
    double n3;
    double n4;
    struct ftuple ftuple1;
    struct ftuple ftuple2;
    const char *file;
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

/* (GENERATOR_OUT_FTUPLE) Generates 5-tuples with "n1" users (src-ips) and
 * "n2" destinations (dst-ips). The base 5-tuple is set by "ftuple1". */
void* generator_policy_superspreader(uint64_t pkt_num,
                                     uint16_t queue_idx,
                                     uint16_t queue_total,
                                     void *args,
                                     void **out);

/* (GENERATOR_OUT_FTUPLE) Generates 5-tuples, each with a unique src-ip and
 * dst-ip. The total number of unique flows is set by "n1". "n2" controls the
 * probability to change the current flow. */
void* generator_policy_nflows(uint64_t pkt_num,
                              uint16_t queue_idx,
                              uint16_t queue_total,
                              void *args,
                              void **out);

/* (GENERATOR_OUT_FTUPLE) Generates 5-tuple "ftuple1" with probability p
 * and 5-tuple "ftuple2" with probability (1-p). The probability p is changed 
 * every "n3" msec from "n1" to "n2". */
void* generator_policy_paths(uint64_t pkt_num,
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

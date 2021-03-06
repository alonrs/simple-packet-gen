#ifndef _TRACE_MAPPING_H_
#define _TRACE_MAPPING_H_

#include "config.h"
#include "packet.h"

struct trace_mapping;

/* Trace mapping status codes */
enum {
    TRACE_MAPPING_VALID = 0,
    TRACE_MAPPING_TRY_AGAIN,
    TRACE_MAPPING_END
};

/**
 * @brief Loads mapping from files, initiate data-structure
 * @param locality_filename If NULL, will generate a uniform locality
 * @param mapping_filename Can not be NULL
 * @param timestamp_filename If NULL, no timestamps are loaded
 * @param num_packets Used if "locality_filename" is NULL, for generating
 * the uniform locality
 * @param num_rules Used if "locality_filename" is NULL, for generating
 * the uniform locality
 * @param num_queues Number of TX queues
 * @returns NULL on error
 */
struct trace_mapping*
trace_mapping_init(const char *mapping_filename,
                   const char *timestamp_filename,
                   const char *locality_filename,
                   uint32_t num_packets,
                   uint32_t num_rules,
                   int num_queues);


/**
 * @brief Destroy the data-structure, join worker threads
 */
void trace_mapping_destroy(struct trace_mapping *trace_mapping);

/**
 * @brief Start the worker threads that generate the packets
 * @returns 0 On success
 */
int trace_mapping_start(struct trace_mapping *trace_mapping);

/**
 * @brief Signal the trace mapping to reset
 */
void trace_mapping_reset(struct trace_mapping *trace_mapping);

/**
 * @brief Returns the next trace packet. If the trace was loaded using a
 * timestamp file, this method also waits the corresponding inter packet delay.
 * @param data[out] The data of the next packet
 * @param txq_idx Index of the current TX queue
 * @returns One of the trace-mapping status codes.
 */
int
trace_mapping_get_next(struct trace_mapping *trace_mapping,
                       void **data,
                       int txq_idx);

/**
 * @brief Modify the speed multiplier for dynamic packet timestamping.
 * @param value The new speed multiplier value; value=1000 stands for 1x
 * speed multiplication; value=0 stands for constant speed.
 */
void trace_mapping_set_multiplier(struct trace_mapping *trace_mapping,
                                  int value);

int trace_mapping_get_multiplier(struct trace_mapping *trace_mapping);

#endif

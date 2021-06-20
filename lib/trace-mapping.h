#ifndef _TRACE_MAPPING_H_
#define _TRACE_MAPPING_H_

#include "packet.h"

struct trace_mapping;

/**
 * @brief Loads mapping from files, initiate data-structure
 * @param locality_filename If NULL, will generate a uniform locality
 * @param mapping_filename Can not be NULL
 * @param timestamp_filename If NULL, no timestamps are loaded
 * @param num_packets Used if "locality_filename" is NULL, for generating
 * the uniform locality
 * @param num_rules Used if "locality_filename" is NULL, for generating
 * @param num_workers Number of workers to generate the packets
 * the uniform locality
 * @returns NULL on error
 */
struct trace_mapping*
trace_mapping_init(const char *locality_filename,
                   const char *mapping_filename,
                   const char *timestamp_filename,
                   uint32_t num_packets,
                   uint32_t num_rules,
                   int num_workers);


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
 * @brief Returns the next trace packet. If the trace was loaded using a
 *  timestamp file, this method also waits the corresponding inter packet delay.
 * @param idx[in|out] The last index of the retrieved 5-tuple, 0 at the 
 * beginning. Should be unique per TX queue
 * @param txq Number of TX queues
 */
int
trace_mapping_get_next(struct trace_mapping *trace_mapping,
                       struct ftuple *ftuple,
                       int *idx,
                       int txq);

#endif

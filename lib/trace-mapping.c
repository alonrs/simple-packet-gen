#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <rte_byteorder.h>
#include "trace-mapping.h"
#include "packet.h"
#include "libcommon/lib/util.h"
#include "libcommon/lib/random.h"
#include "libcommon/lib/vector.h"
#include "libcommon/lib/map.h"
#include "libcommon/lib/perf.h"

#define NUM_FIELDS  5
#define RING_SIZE 256

#define RING_ELEMENT_STATUS_EMPTY 0
#define RING_ELEMENT_STATUS_FULL 1

struct packet {
    struct map_node node;
    struct ftuple ftuple;
    int priority;
    int locality;
};


struct uniform_locality_args {
    int num_of_packets;
    int num_of_rules;
};

struct worker_args {
    struct trace_mapping *trace_mapping;
    int current_worker;
};

ALIGNED_STRUCT(CACHE_LINE_SIZE, ring) {
    struct ftuple ftuple;
    uint64_t timestamp;
    volatile int status;
};

struct trace_mapping {
    struct ring ring[RING_SIZE];
    struct vector *locality;
    struct vector *timestamps;
    struct map *mapping;
    pthread_t *threads;
    int num_workers;
    uint64_t timestamp;
    atomic_int stop;
    atomic_int speed_multiplier;
};

/**
 * @brief Reads a list of integers from file.
 * @brief args Filename to read from
 * @brief returns A vector of uint64_t
 */
static void*
load_integers_from_file(void *args)
{
    struct vector *vector;
    const char *filename;
    long value;
    FILE *f;

    filename = (const char*)args;
    f = fopen(filename, "r");
    if (!f) {
        return NULL;
    }

    vector = vector_init(sizeof(uint64_t));
    if (!vector) {
        return NULL;
    }

    while (fscanf(f,"%ld\n", &value) == 1) {
        vector_push_unsafe(vector, &value);
    }

    fclose(f);
    return vector;
}

/**
 * @brief Loads mapping from filename
 * @param args Filename to load the mapping from
 * @returns A map from priority to packet
 */
static void*
load_mapping_from_file(void *args)
{
    struct map *map;
    const char *filename;
    struct packet *packet;
    uint32_t hash;
    int line_num;
    long value;
    FILE *f;

    line_num = 0;
    filename = (const char*)args;
    f = fopen(filename, "r");
    if (!f) {
        return NULL;
    }

    map = malloc(sizeof(*map));
    map_init(map, 8192);

    while (1) {

        packet = malloc(sizeof(*packet));
        packet->locality = line_num;

        if (fscanf(f, "%d:", &packet->priority) != 1) {
            break;
        }

        /* Get 5-tuple */
        for (int i=0; i<NUM_FIELDS; ++i) {
            if (!fscanf(f, "%ld", &value)) {
                printf("Cannot process rule in line %d"
                       "(priority %d): got only %d/%d headers!",
                       line_num+1,
                       packet->priority,
                       i,
                       NUM_FIELDS);
            }
            switch (i) {
            case 0:
                packet->ftuple.ip_proto = value;
                break;
            case 1:
                packet->ftuple.src_ip = rte_cpu_to_be_32(value);
                break;
            case 2:
                packet->ftuple.dst_ip = rte_cpu_to_be_32(value);
                break;
            case 3:
                packet->ftuple.src_port = rte_cpu_to_be_16(value);
                break;
            case 4:
                packet->ftuple.dst_port = rte_cpu_to_be_16(value);
                break;
            }
        }

        hash = hash_int(packet->locality, 0);
        map_insert(map, &packet->node, hash);
        line_num++;
    }

    fclose(f);
    return map;
}

/**
 * @brief Generates a vector with uniform uint32_t distribution
 * @param num_of_packets Number of packets in trace
 * @param num_of_rules Number of rules in the ruleset
 * @returns A vector of uint32_t
 */
static void*
generate_uniform_locality(void* args)
{
    struct uniform_locality_args *params;
    struct vector *vector;
    uint32_t value;

    params = (struct uniform_locality_args*)args;
    vector = vector_init(sizeof(uint32_t));
    if (!vector) {
        return NULL;
    }

    for (size_t i=0; i<params->num_of_packets; ++i) {
        value = random_uint32() % (params->num_of_rules-1);
        vector_push_unsafe(vector, &value);
    }

    return vector;
}

static void*
worker_start(void *args)
{
    struct worker_args *worker_args;
    struct trace_mapping *trace_mapping;
    struct vector_iterator it_locality;
    struct vector_iterator it_timestamp;
    struct packet *packet;
    struct ring *ring;
    uint32_t hash;
    long *timestamp;
    long *locality;
    int idx;

    worker_args = (struct worker_args*)args;
    trace_mapping = worker_args->trace_mapping;

    /* Init vector iterators to point to #element == "worker-num" */
    it_locality = vector_begin(trace_mapping->locality);
    it_timestamp = vector_begin(trace_mapping->timestamps);
    idx = worker_args->current_worker;
    for (int i=0; i<worker_args->current_worker; i++) {
        vector_iterator_next(&it_locality);
        vector_iterator_next(&it_timestamp);
    }

    while(!trace_mapping->stop) {

        ring = &trace_mapping->ring[idx];
        if (ring->status == RING_ELEMENT_STATUS_FULL) {
            continue;
        }

        timestamp = vector_iterator_valid(&it_timestamp) ? 
                    (long*)vector_iterator_get(&it_timestamp) : 
                    NULL;
        locality = vector_iterator_valid(&it_locality) ?
                   (long*)vector_iterator_get(&it_locality) :
                   NULL;

        /* Got to the end of the mapping, stop */
        if (!locality) {
            break;
        }

        /* Point to the relevant 5-tuple */
        hash = hash_int(*locality, 0);
        MAP_FOR_EACH_WITH_HASH(packet, node, hash, trace_mapping->mapping) {
            if (packet->locality == *locality) {
                ring->ftuple = packet->ftuple;
            }
        }

        /* Set additional values, timestamp in nanosec */
        ring->timestamp = trace_mapping->speed_multiplier *
                          (timestamp ? *timestamp : 0);
        ring->status = RING_ELEMENT_STATUS_FULL;

        /* Continue to the next packet */
        for (int i=0; i<trace_mapping->num_workers; i++) {
            vector_iterator_next(&it_locality);
            vector_iterator_next(&it_timestamp);
        }
        idx = (idx + trace_mapping->num_workers) % RING_SIZE;

    };

    free(worker_args);
    pthread_exit(NULL);
}

void
trace_mapping_destroy(struct trace_mapping *trace_mapping)
{
    struct packet *packet;
    if (!trace_mapping) {
        return;
    }

    if (trace_mapping->threads) {
        atomic_store(&trace_mapping->stop, 1);
        for (int i=0; i<trace_mapping->num_workers; i++) {
            pthread_join(trace_mapping->threads[i], NULL);
        }
    }
    free(trace_mapping->threads);

    vector_destroy(trace_mapping->locality);
    vector_destroy(trace_mapping->timestamps);

    MAP_FOR_EACH(packet, node, trace_mapping->mapping) {
        free(packet);
    }
    map_destroy(trace_mapping->mapping);

    free(trace_mapping);
}

struct trace_mapping*
trace_mapping_init(const char *mapping_filename,
                   const char *timestamp_filename,
                   const char *locality_filename,
                   int num_workers,
                   uint32_t num_packets,
                   uint32_t num_rules)
{
    struct uniform_locality_args args;
    struct trace_mapping *trace_mapping;
    pthread_t workers[3];
    char bitmask;

    trace_mapping = malloc(sizeof(*trace_mapping));
    if (!trace_mapping) {
        return NULL;
    }

    memset(trace_mapping, 0, sizeof(*trace_mapping));
    bitmask = 0;


    trace_mapping->threads = malloc(sizeof(pthread_t)*num_workers);
    trace_mapping->num_workers = num_workers;
    trace_mapping->timestamp = 0;
    atomic_init(&trace_mapping->speed_multiplier, 1000);
    atomic_init(&trace_mapping->stop, 0);

    if (!trace_mapping->threads) {
        trace_mapping_destroy(trace_mapping);
        return NULL;
    }

    if (mapping_filename) {
        printf("Reading mapping from \"%s\"...\n", mapping_filename);

        pthread_create(&workers[0],
                       NULL,
                       load_mapping_from_file,
                       (void*)mapping_filename);
        bitmask |= 1;
    }

    if (locality_filename) {
        printf("Reading locality from \"%s\"...\n", locality_filename);
        pthread_create(&workers[1],
                       NULL,
                       load_integers_from_file,
                       (void*)locality_filename);
        bitmask |= 2;
    } else {
        args.num_of_packets = num_packets;
        args.num_of_rules = num_rules;
        pthread_create(&workers[1],
                       NULL,
                       generate_uniform_locality,
                       (void*)&args);
        bitmask |= 2;
    }

    if (timestamp_filename) {
        printf("Reading timestamps from \"%s\"...\n", timestamp_filename);
        pthread_create(&workers[2],
                       NULL,
                       load_integers_from_file,
                       (void*)timestamp_filename);
        bitmask |= 4;
    }

    /* Wait for threads */
    if (bitmask&1) {
        pthread_join(workers[0], (void**)&trace_mapping->mapping);
    }
    if (bitmask&2) {
        pthread_join(workers[1], (void**)&trace_mapping->locality);
    }
    if (bitmask&4) {
        pthread_join(workers[2], (void**)&trace_mapping->timestamps);
    }

    for (int i=0; i<RING_SIZE; i++) {
        trace_mapping->ring[i].status = RING_ELEMENT_STATUS_EMPTY;
    }

    return trace_mapping;
}

int
trace_mapping_start(struct trace_mapping *trace_mapping)
{
    struct worker_args *worker_args;

    for (int i=0; i<trace_mapping->num_workers; i++) {
        worker_args = xmalloc(sizeof(*worker_args));
        worker_args->current_worker = i;
        worker_args->trace_mapping = trace_mapping;
        pthread_create(&trace_mapping->threads[i],
                       NULL,
                       worker_start,
                       worker_args);
    }

    return 0;
}

int
trace_mapping_get_next(struct trace_mapping *trace_mapping,
                       struct ftuple *ftuple,
                       int *idx,
                       int txq)
{
    struct ring *ring;
    uint64_t wait_until;
    uint64_t diff_ts;

    ring = &trace_mapping->ring[*idx];
    while (ring->status == RING_ELEMENT_STATUS_EMPTY) {
        if (trace_mapping->stop) {
            return 1;
        }
    }

    /* Inter packet delays are in micro second */
    diff_ts = ring->timestamp;
    wait_until = trace_mapping->timestamp + diff_ts;
    while (get_time_ns() < wait_until);

    trace_mapping->timestamp = get_time_ns();
    ring->status = RING_ELEMENT_STATUS_EMPTY;

    *ftuple = ring->ftuple;
    *idx = (*idx+txq) % RING_SIZE;

    return 0;
}

void
trace_mapping_set_multiplier(int value)
{
    atomic_store(&trace_mapping->speed_multiplier, value);
}


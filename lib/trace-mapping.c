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
#include "libcommon/lib/thread-sync.h"
#include "libcommon/lib/perf.h"

#define NUM_FIELDS  5

#define NUM_WORKERS 8

#define SIGNAL_RUNNING 0
#define SIGNAL_STOP 1
#define SIGNAL_RESET 2

enum worker_status {
    WORKER_STATUS_SUCCESS=0,
    WORKER_STATUS_FULL,
    WORKER_STATUS_END
};

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

struct packet_data {
    char data[PACKET_SIZE];
    int64_t ipg_ms;
};

struct worker_context {
    struct trace_mapping *trace_mapping;
    struct vector_iterator it_locality;
    struct vector_iterator it_timestamp; 
    int worker_idx;
    struct packet_data *mem;
};

struct queue_context {
    uint64_t timestamp;
    uint64_t idx;
    struct packet_data *mem;
};

struct trace_mapping {
    struct worker_context *worker_context;
    struct queue_context *queue_context;
    struct vector *timestamps;
    struct vector *locality;
    struct packet_data *mem;
    struct map *mapping;
    uint64_t num_packets;
    int queue_num;
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

static void
trace_mapping_clear(struct trace_mapping *trace_mapping)
{
    int adaptive;

    adaptive = atomic_load(&trace_mapping->speed_multiplier) != 0;
    if (adaptive) {
        atomic_init(&trace_mapping->speed_multiplier, 1000);
    }
}

static void
allocate_memory(struct trace_mapping *trace_mapping)
{
    size_t size;

    size = trace_mapping->num_packets * sizeof(struct packet_data);
    printf("Allocating %.3lf MB for packet data...\n",
           (double)size / 1024 / 1024);
    trace_mapping->mem = xmalloc(size);
}

static void
worker_init(struct worker_context *ctx)
{
    ctx->it_locality = vector_begin(ctx->trace_mapping->locality);
    ctx->it_timestamp = vector_begin(ctx->trace_mapping->timestamps);
    ctx->mem = ctx->trace_mapping->mem;

    for (int i=0; i<ctx->worker_idx; i++) {
        vector_iterator_next(&ctx->it_locality);
        vector_iterator_next(&ctx->it_timestamp);
        ctx->mem++;
    }
}

/* Returns 0 on success */
static int
worker_generate_packet(struct worker_context *ctx)
{
    struct ftuple ftuple;
    struct packet *packet;
    long *timestamp;
    long *locality;
    uint32_t hash;
    bool found;

    timestamp = vector_iterator_valid(&ctx->it_timestamp) ? 
                (long*)vector_iterator_get(&ctx->it_timestamp) : 
                NULL;

    locality = vector_iterator_valid(&ctx->it_locality) ?
               (long*)vector_iterator_get(&ctx->it_locality) :
               NULL;

    /* Got to the end of the mapping */
    if (!locality) {
        return 1;
    }

    found = false;

    /* Point to the relevant 5-tuple */
    hash = hash_int(*locality, 0);
    MAP_FOR_EACH_WITH_HASH(packet, node, hash, ctx->trace_mapping->mapping) {
        if (packet->locality == *locality) {
            ftuple = packet->ftuple;
	    found = true;
            break;
        }
    }

    if (!found) {
	printf("Error - 5-tuple was not found with locality\n");
	return 1;
    }

    packet_generate_ftuple_raw(ctx->mem->data,
                               NULL,
                               NULL,
                               PACKET_SIZE,
                               true,
                               &ftuple,
                               false);

    /* Set additional values, timestamp in nanosec */
    ctx->mem->ipg_ms = timestamp ? *timestamp : 0;

    /* Continue to the next packet */
    for (int i=0; i<NUM_WORKERS; i++) {
        vector_iterator_next(&ctx->it_locality);
        vector_iterator_next(&ctx->it_timestamp);
        ctx->mem++;
    }

    return 0;
}

static void*
worker_start(void *args)
{
    struct worker_context *ctx;
    uint64_t retval;

    ctx = (struct worker_context*)args;
    retval = 0;

    while(!retval) {
        retval = worker_generate_packet(ctx);
    };
    pthread_exit(NULL);
}

void
trace_mapping_destroy(struct trace_mapping *trace_mapping)
{
    struct packet *packet;
    if (!trace_mapping) {
        return;
    }

    vector_destroy(trace_mapping->locality);
    vector_destroy(trace_mapping->timestamps);
    free(trace_mapping->mem);

    MAP_FOR_EACH(packet, node, trace_mapping->mapping) {
        free(packet);
    }
    map_destroy(trace_mapping->mapping);

    free(trace_mapping->worker_context);
    free(trace_mapping);
}

struct trace_mapping*
trace_mapping_init(const char *mapping_filename,
                   const char *timestamp_filename,
                   const char *locality_filename,
                   uint32_t num_packets,
                   uint32_t num_rules,
                   int queue_num)
{
    struct uniform_locality_args args;
    struct trace_mapping *trace_mapping;
    struct worker_context *ctx;
    pthread_t workers[3];
    pthread_t generator_workers[NUM_WORKERS];
    char bitmask;
    size_t elems;

    trace_mapping = malloc(sizeof(*trace_mapping));
    if (!trace_mapping) {
        return NULL;
    }

    memset(trace_mapping, 0, sizeof(*trace_mapping));
    bitmask = 0;

    trace_mapping_clear(trace_mapping);

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

    trace_mapping->num_packets = vector_size(trace_mapping->locality);
    allocate_memory(trace_mapping);

    /* Generate the worker context */
    elems = sizeof(struct worker_context)*NUM_WORKERS;
    trace_mapping->worker_context = xmalloc(elems);
    for (int i=0; i<NUM_WORKERS; i++) {
        ctx = &trace_mapping->worker_context[i];
        ctx->worker_idx = i;
        ctx->trace_mapping = trace_mapping;
        worker_init(ctx);
        pthread_create(&generator_workers[i],
                       NULL,
                       worker_start,
                       &trace_mapping->worker_context[i]);
    }

    printf("Waiting for %d generator workers to generate packet data...\n",
           NUM_WORKERS);

    for (int i=0; i<NUM_WORKERS; i++) {
        pthread_join(generator_workers[i], NULL);
    }

    /* Generate queue context */
    trace_mapping->queue_num = queue_num;
    trace_mapping->queue_context = xmalloc(sizeof(struct queue_context) *
                                           queue_num);
    for (int i=0; i<queue_num; i++) {
        trace_mapping->queue_context[i].timestamp = 0;
        trace_mapping->queue_context[i].idx = i;
        trace_mapping->queue_context[i].mem = trace_mapping->mem + i;
    }

    return trace_mapping;
}

void
trace_mapping_reset(struct trace_mapping *trace_mapping)
{
    for (int i=0; i<trace_mapping->queue_num; i++) {
        trace_mapping->queue_context[i].timestamp = 0;
        trace_mapping->queue_context[i].idx = i;
        trace_mapping->queue_context[i].mem = trace_mapping->mem + i;
    }
}

void
trace_mapping_set_multiplier(struct trace_mapping *trace_mapping,
                             int value)
{
    atomic_store(&trace_mapping->speed_multiplier, value);
}

int
trace_mapping_get_multiplier(struct trace_mapping *trace_mapping)
{
    return atomic_load(&trace_mapping->speed_multiplier);
}

int
trace_mapping_get_next(struct trace_mapping *trace_mapping,
                       void **data,
                       int txq_idx)
{
    struct queue_context *ctx;
    uint64_t wait_until;
    uint64_t diff_ts;

    ctx = &trace_mapping->queue_context[txq_idx];

    if (ctx->idx >= trace_mapping->num_packets) {
        return TRACE_MAPPING_END;
    }

    /* Inter packet delays are in micro second */
    diff_ts = ctx->mem->ipg_ms *
              ((double)trace_mapping->speed_multiplier / 1000);
    wait_until = ctx->timestamp + diff_ts;
    if (get_time_ns() < wait_until) {
        return TRACE_MAPPING_TRY_AGAIN;
    }

    ctx->timestamp = get_time_ns();
    *data = (void*)ctx->mem->data;
    ctx->mem += trace_mapping->queue_num;
    ctx->idx += trace_mapping->queue_num;
    return TRACE_MAPPING_VALID;
}


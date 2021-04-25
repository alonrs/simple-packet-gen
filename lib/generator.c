#include <math.h>
#include <rte_byteorder.h>
#include <netinet/in.h>

#include "common.h"
#include "generator.h"

#define STATE_KEY 1600

/* Initialize ssnf args based on queue index */
static void
ssnf_args_init(struct ssnf_args *ssnf_args,
               uint16_t queue_idx,
               uint16_t queue_total,
               void *args)
{
    get_void_arg_bytes(ssnf_args, args, sizeof(*ssnf_args), false);
    /* Each queue has its share */
    if (!queue_idx) {
        ssnf_args->flow_num = ceil(ssnf_args->flow_num / queue_total);
    } else {
        ssnf_args->flow_num = floor(ssnf_args->flow_num / queue_total);
    }
}

void*
generator_policy_superspreader(uint64_t pkt_num,
                               uint16_t queue_idx,
                               uint16_t queue_total,
                               struct ftuple *ftuple,
                               void *args)
{
    /* Thread specfic state */
    struct {
        struct ssnf_args ssnf_args;
        int flow_num;
        uint32_t dst_ip;
        uint16_t dst_port;
        int shift;
    } *state;

    /* First packet, parse initial args, set state */
    if (!pkt_num) {
        /* Memory allocation per queue (core) */
        state = xmalloc(sizeof(*state));
        /* Initialize values */
        ssnf_args_init(&state->ssnf_args, queue_idx, queue_total, args);
        memcpy(ftuple, &state->ssnf_args.base, sizeof(*ftuple));
        state->dst_ip = rte_be_to_cpu_32(ftuple->dst_ip);
        state->dst_port = rte_be_to_cpu_16(ftuple->dst_port);
        state->shift = queue_idx;
    }
    /* Get state from args */
    else {
        state = args;
    }

    /* Calculate shift from base */
    state->shift += queue_total;
    state->flow_num++;

    if (state->flow_num == state->ssnf_args.flow_num) {
        state->flow_num = 0;
        state->shift = queue_idx;
    }

    /* Update values */
    ftuple->dst_ip = rte_cpu_to_be_32(state->dst_ip + state->shift);
    ftuple->dst_port = rte_cpu_to_be_16(state->dst_port + state->shift);

    return state;
}

void*
generator_policy_nflows(uint64_t pkt_num,
                        uint16_t queue_idx,
                        uint16_t queue_total,
                        struct ftuple *ftuple,
                        void *args)
{
    /* Thread specfic state */
    struct {
        struct ssnf_args ssnf_args;
        int flow_num;
        uint32_t dst_ip;
        uint32_t src_ip;
        int shift;
    } *state;

    /* First packet, parse initial args, set state */
    if (!pkt_num) {
        /* Memory allocation per queue (core) */
        state = xmalloc(sizeof(*state));
        /* Initialize values */
        ssnf_args_init(&state->ssnf_args, queue_idx, queue_total, args);
        memcpy(ftuple, &state->ssnf_args.base, sizeof(*ftuple));
        state->dst_ip = rte_be_to_cpu_32(ftuple->dst_ip);
        state->src_ip = rte_be_to_cpu_32(ftuple->src_ip);
        state->shift = queue_idx;
    }
    /* Get state from args */
    else {
        state = args;
    }

    /* Calculate shift from base */
    state->shift += queue_total;
    state->flow_num++;

    if (state->flow_num == state->ssnf_args.flow_num) {
        state->flow_num = 0;
        state->shift = queue_idx;
    }

    /* Update values */
    ftuple->dst_ip = rte_cpu_to_be_32(state->dst_ip + state->shift);
    ftuple->src_ip = rte_cpu_to_be_32(state->src_ip + state->shift);

    return state;
}

void*
generator_policy_pcap(uint64_t pkt_num,
                      uint16_t queue_idx,
                      uint16_t queue_total,
                      struct ftuple *ftuple,
                      void *args)
{

}

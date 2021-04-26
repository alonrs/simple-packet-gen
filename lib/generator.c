#include <math.h>
#include <rte_byteorder.h>
#include <netinet/in.h>
#include <pcap/pcap.h>

#include "common.h"
#include "generator.h"

#define STATE_KEY 1600

/* The state for PCAP policy */
struct pcap_state {
    pcap_t *p;
    struct raw_packet raw;
};

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
                               void *args,
                               void **out)
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
        state->dst_ip = rte_be_to_cpu_32(state->ssnf_args.base.dst_ip);
        state->dst_port = rte_be_to_cpu_16(state->ssnf_args.base.dst_port);
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

    /* Update 5-tuple values */
    state->ssnf_args.base.dst_ip =
            rte_cpu_to_be_32(state->dst_ip + state->shift);
    state->ssnf_args.base.dst_port =
            rte_cpu_to_be_16(state->dst_port + state->shift);

    /* Output is a pointer to the 5-tuple */
    *out = &state->ssnf_args.base;

    return state;
}

void*
generator_policy_nflows(uint64_t pkt_num,
                        uint16_t queue_idx,
                        uint16_t queue_total,
                        void *args,
                        void **out)
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
        state->dst_ip = rte_be_to_cpu_32(state->ssnf_args.base.dst_ip);
        state->src_ip = rte_be_to_cpu_32(state->ssnf_args.base.src_ip);
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
    state->ssnf_args.base.dst_ip =
            rte_cpu_to_be_32(state->dst_ip + state->shift);
    state->ssnf_args.base.src_ip =
            rte_cpu_to_be_32(state->src_ip + state->shift);

    /* Output is a pointer to the 5-tuple */
    *out = &state->ssnf_args.base;

    return state;
}

/* Callback for pcap_dispatch method called in "generator_policy_pcap" */
static void
pcap_reader_callback(uint8_t *user,
                     const struct pcap_pkthdr* h,
                     const uint8_t *bytes)
{
    struct pcap_state *state = (struct pcap_state*)user;
    /* Update state with the bytes of the current packet */
    state->raw.bytes = (const char*)bytes;
    state->raw.size = h->caplen;
}

void*
generator_policy_pcap(uint64_t pkt_num,
                      uint16_t queue_idx,
                      uint16_t queue_total,
                      void *args,
                      void **out)
{

    /* Thread specific state */
    struct pcap_state *state;
    int ret;

    /* First packet, parse initial args, set state */
    if (!pkt_num) {
        /* Memory allocation per queue (core) */
        state = xmalloc(sizeof(*state));
        memset(state, 0, sizeof(*state));

        /* Initialize values */
        const char *pcap_fname = args;
        char error[PCAP_ERRBUF_SIZE];
        state->p = pcap_open_offline(pcap_fname, error);
        if (!state->p) {
            printf("Cannot open PCAP file: %s\n", error);
            exit(EXIT_FAILURE);
        }
    }
    /* Get state from args */
    else {
        state = args;
    }

    /* Parse 1 pcaket from PCAP */
    ret = pcap_dispatch(state->p, 1, pcap_reader_callback, (uint8_t*)state);
    if (ret == PCAP_ERROR) {
        printf("Error reading PCAP files: %s \n",
               pcap_geterr(state->p));
        exit(1);
    }

    /* Return a pointer to raw packet */
    *out = &state->raw;

    return state;
}

#include <stdint.h>
#include <math.h>
#include <rte_byteorder.h>
#include <netinet/in.h>
#include <pcap/pcap.h>

#include "libcommon/lib/random.h"
#include "common.h"
#include "generator.h"

#define STATE_KEY 1600

/* The state for PCAP policy */
struct pcap_state {
    pcap_t *p;
    struct raw_packet raw;
};

void*
generator_policy_superspreader(uint64_t pkt_num,
                               uint16_t queue_idx,
                               uint16_t queue_total,
                               void *args,
                               void **out)
{
    /* Thread specfic state */
    struct {
        struct policy_knobs knobs;
        uint32_t src_ip;
        uint32_t dst_ip;
        int src_counter;
        int dst_counter;
    } *state;

    /* First packet, parse initial args, set state */
    if (!pkt_num) {
        /* Memory allocation per core, initialize values */
        state = xmalloc(sizeof(*state));
        get_void_arg_bytes(&state->knobs,
                           args,
                           sizeof(struct policy_knobs),
                           false);
        state->src_ip = rte_be_to_cpu_32(state->knobs.ftuple1.src_ip);
        state->dst_ip = rte_be_to_cpu_32(state->knobs.ftuple1.dst_ip);
        state->src_counter = 0;
        state->dst_counter = 0;
    }
    /* Get state from args */
    else {
        state = args;
    }

    if (state->src_counter >= state->knobs.n1) {
        state->src_counter = 0;
        state->dst_counter++;
    }

    if (state->dst_counter >= state->knobs.n2) {
        state->dst_counter = 0;
    }

    /* Update 5-tuple values */
    state->knobs.ftuple1.src_ip =
            rte_cpu_to_be_32(state->src_ip + state->src_counter);
    state->knobs.ftuple1.dst_ip =
            rte_cpu_to_be_32(state->dst_ip + state->dst_counter);

    /* Update counter */
    state->src_counter++;

    /* Output is a pointer to the 5-tuple */
    *out = &state->knobs.ftuple1;

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
        struct policy_knobs knobs;
        uint32_t src_ip;
        uint32_t dst_ip;
        int counter;
    } *state;

    /* First packet, parse initial args, set state */
    if (!pkt_num) {
        /* Memory allocation per core, initialize values */
        state = xmalloc(sizeof(*state));
        get_void_arg_bytes(&state->knobs,
                           args,
                           sizeof(struct policy_knobs),
                           false);
        state->src_ip = rte_be_to_cpu_32(state->knobs.ftuple1.src_ip);
        state->dst_ip = rte_be_to_cpu_16(state->knobs.ftuple1.dst_ip);
        state->counter = 0;
    }
    /* Get state from args */
    else {
        state = args;
    }

    if (state->counter == state->knobs.n1) {
        state->counter = 0;
    }

    /* Update 5-tuple values */
    state->knobs.ftuple1.src_ip =
            rte_cpu_to_be_32(state->src_ip + state->counter);
    state->knobs.ftuple1.dst_ip =
            rte_cpu_to_be_32(state->dst_ip + state->counter);

    /* Update counter with probability "n2" */
    if (random_coin(state->knobs.n2)) {
        state->counter++;
    }

    /* Output is a pointer to the 5-tuple */
    *out = &state->knobs.ftuple1;

    return state;
}

void*
generator_policy_paths(uint64_t pkt_num,
                       uint16_t queue_idx,
                       uint16_t queue_total,
                       void *args,
                       void **out)
{
    /* Thread specfic state */
    struct {
        struct policy_knobs knobs;
        uint64_t timestamp;
        int phase;
    } *state;
    double p;

    /* First packet, parse initial args, set state */
    if (!pkt_num) {
        /* Memory allocation per core, initialize values */
        state = xmalloc(sizeof(*state));
        get_void_arg_bytes(&state->knobs,
                           args,
                           sizeof(struct policy_knobs),
                           false);
        state->knobs.n3 *= 1e6; /* From ms to ns */
        state->timestamp = get_time_ns();
        state->phase = 0;
    }
    /* Get state from args */
    else {
        state = args;
    }

    /* Change phase? */
    if (get_time_ns() - state->timestamp >= state->knobs.n3) {
        state->phase = (state->phase+1)&0x1;
        state->timestamp = get_time_ns();
    }

    /* Choose path by probability */
    /* Output is a pointer to the 5-tuple */
    p = (!state->phase) ? state->knobs.n1 : state->knobs.n2;
    if (random_coin(p)) {
        *out = &state->knobs.ftuple1;
    } else {
        *out = &state->knobs.ftuple2;
    }

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
        struct policy_knobs knobs;
        char error[PCAP_ERRBUF_SIZE];

        get_void_arg_bytes(&knobs,
                           args,
                           sizeof(struct policy_knobs),
                           false);
        state->p = pcap_open_offline(knobs.file, error);
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
    
    /* In case no more packets */
    if (ret != 1) {
        *out = NULL;
    } else {
        /* Return a pointer to raw packet */
        *out = &state->raw;
    }

    return state;
}

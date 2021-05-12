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
        uint64_t phase_counter;        /* Counter packets for phase */
        uint64_t packets_per_phase;    /* Number of packets per phase */
        uint32_t src_ip;
        uint32_t dst_ip;
        int src_counter;
        int dst_counter;
        int phase_src_end;        /* src-ip start value for phase */
        int phase_src_start;      /* src-ip end value for phase */
        int phase_srcip_num;      /* Number of sources IPs per phase */
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
        state->packets_per_phase = state->knobs.n4;
        state->phase_srcip_num = state->knobs.n3 * queue_total;
        state->src_counter = queue_idx;
        state->dst_counter = 0;
        state->phase_src_start = 0;
        state->phase_src_end = state->phase_srcip_num;
        state->phase_counter = 0;
    }
    /* Get state from args */
    else {
        state = args;
    }

    if (state->src_counter >= state->phase_src_end) {
        state->src_counter = state->phase_src_start + queue_idx;
        state->dst_counter++;
    }

    if (state->dst_counter >= state->knobs.n2) {
        state->dst_counter = 0;
    }

    /* Update 5-tuple values */
    state->knobs.ftuple1.src_ip =
            rte_cpu_to_be_32(state->src_ip + state->src_counter * 0x010000);
    state->knobs.ftuple1.dst_ip =
            rte_cpu_to_be_32(state->src_ip + state->src_counter * 0x010000 + 
                             state->dst_counter);

    /* Update counters */
    state->src_counter += queue_total;
    state->phase_counter++;

    /* Update pbatch. */
    if (state->phase_counter >= state->packets_per_phase) {
        state->phase_counter = 0;
        state->phase_src_start += state->phase_srcip_num;
        state->phase_src_end += state->phase_srcip_num;
        if (state->phase_src_start >= state->knobs.n1) {
            state->phase_src_start = 0;
            state->phase_src_end = state->phase_srcip_num;
        }
        if (state->phase_src_end >= state->knobs.n1) {
            state->phase_src_end = state->knobs.n1;
        }
        state->src_counter = state->phase_src_start + queue_idx; 
    }

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
        uint32_t ip;
        int counter;
        uint64_t timestamp;
        int phase;
        int p;
    } *state;

    /* First packet, parse initial args, set state */
    if (!pkt_num) {
        /* Memory allocation per core, initialize values */
        state = xmalloc(sizeof(*state));
        get_void_arg_bytes(&state->knobs,
                           args,
                           sizeof(struct policy_knobs),
                           false);
        state->knobs.n3 *= 1e6; /* From us to ns */
        state->ip = rte_be_to_cpu_32(state->knobs.ftuple1.src_ip);
        state->counter = 0;
        state->timestamp = get_time_ns();
        state->phase = 0;
        state->knobs.n1 *= queue_total;
        state->knobs.n2 *= queue_total;
        state->p = state->knobs.n1;
    }
    /* Get state from args */
    else {
        state = args;
    }

    if (state->counter > state->knobs.n4) {
        state->counter = 0;
    }

    /* Update 5-tuple values */
    state->knobs.ftuple1.src_ip = rte_cpu_to_be_32(state->ip + state->counter);

    /* Change phase? */
    if (get_time_ns() - state->timestamp >= state->knobs.n3) {
        state->phase = !state->phase;
        state->timestamp = get_time_ns();
        state->p = (!state->phase) ? state->knobs.n1 : state->knobs.n2;
    }

    /* Choose path by probability */
    /* Output is a pointer to the 5-tuple */
    if (queue_idx < state->p) {
    	*out = &state->knobs.ftuple1;
        /* state->knobs.ftuple1.src_port = rte_cpu_to_be_16(1000); */
    } else {
    	*out = &state->knobs.ftuple2;
        /* state->knobs.ftuple1.src_port = rte_cpu_to_be_16(2000); */
    }

    /* Update counter */
    state->counter++;

    /* Output is a pointer to the 5-tuple */
    *out = &state->knobs.ftuple1;

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

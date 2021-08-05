#include <stdint.h>
#include <math.h>
#include <rte_byteorder.h>
#include <netinet/in.h>
#include <pcap/pcap.h>

#include "libcommon/lib/random.h"
#include "common.h"
#include "generator.h"
#include "trace-mapping.h"

#define STATE_KEY 1600

/* The state for PCAP policy */
struct pcap_state {
    pcap_t *p;
    struct raw_packet raw;
};

void
generator_policy_superspreader(uint64_t pkt_num,
                               uint16_t queue_idx,
                               uint16_t queue_total,
                               struct generator_state *generator_state,
                               void **out)
{
    /* Thread specfic state */
    struct {
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
        state->src_ip = rte_be_to_cpu_32(generator_state->knobs.ftuple1.src_ip);
        state->dst_ip = rte_be_to_cpu_32(generator_state->knobs.ftuple1.dst_ip);
        state->packets_per_phase = generator_state->knobs.n4;
        state->phase_srcip_num = generator_state->knobs.n3 * queue_total;
        state->src_counter = queue_idx;
        state->dst_counter = 0;
        state->phase_src_start = 0;
        state->phase_src_end = state->phase_srcip_num;
        state->phase_counter = 0;
    }
    /* Get state from args */
    else {
        state = generator_state->args;
    }

    if (state->src_counter >= state->phase_src_end) {
        state->src_counter = state->phase_src_start + queue_idx;
        state->dst_counter++;
    }

    if (state->dst_counter >= generator_state->knobs.n2) {
        state->dst_counter = 0;
    }

    /* Update 5-tuple values */
    generator_state->knobs.ftuple1.src_ip =
            rte_cpu_to_be_32(state->src_ip + state->src_counter * 0x010000);
    generator_state->knobs.ftuple1.dst_ip =
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
        if (state->phase_src_start >= generator_state->knobs.n1) {
            state->phase_src_start = 0;
            state->phase_src_end = state->phase_srcip_num;
        }
        if (state->phase_src_end >= generator_state->knobs.n1) {
            state->phase_src_end = generator_state->knobs.n1;
        }
        state->src_counter = state->phase_src_start + queue_idx; 
    }

    /* Output is a pointer to the 5-tuple */
    *out = &generator_state->knobs.ftuple1;

    generator_state->args = state;
    generator_state->status = GENERATOR_VALID;
}

void
generator_policy_nflows(uint64_t pkt_num,
                        uint16_t queue_idx,
                        uint16_t queue_total,
                        struct generator_state *generator_state,
                        void **out)
{
    /* Thread specfic state */
    struct {
        uint32_t src_ip;
        uint32_t dst_ip;
        int counter;
    } *state;

    /* First packet, parse initial args, set state */
    if (!pkt_num) {
        /* Memory allocation per core, initialize values */
        state = xmalloc(sizeof(*state));
        state->src_ip = rte_be_to_cpu_32(generator_state->knobs.ftuple1.src_ip);
        state->dst_ip = rte_be_to_cpu_16(generator_state->knobs.ftuple1.dst_ip);
        state->counter = 0;
    }
    /* Get state from args */
    else {
        state = generator_state->args;
    }

    if (state->counter == generator_state->knobs.n1) {
        state->counter = 0;
    }

    /* Update 5-tuple values */
    generator_state->knobs.ftuple1.src_ip =
            rte_cpu_to_be_32(state->src_ip + state->counter);
    generator_state->knobs.ftuple1.dst_ip =
            rte_cpu_to_be_32(state->dst_ip + state->counter);

    /* Update counter with probability "n2" */
    if (random_coin(generator_state->knobs.n2)) {
        state->counter++;
    }

    /* Output is a pointer to the 5-tuple */
    *out = &generator_state->knobs.ftuple1;

    generator_state->args = state;
    generator_state->status = GENERATOR_VALID;
}

void
generator_policy_paths(uint64_t pkt_num,
                       uint16_t queue_idx,
                       uint16_t queue_total,
                       struct generator_state *generator_state,
                       void **out)
{
    /* Thread specfic state */
    struct {
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
        generator_state->knobs.n3 *= 1e6; /* From us to ns */
        state->ip = rte_be_to_cpu_32(generator_state->knobs.ftuple1.src_ip);
        state->counter = 0;
        state->timestamp = get_time_ns();
        state->phase = 0;
        generator_state->knobs.n1 *= queue_total;
        generator_state->knobs.n2 *= queue_total;
        state->p = generator_state->knobs.n1;
    }
    /* Get state from args */
    else {
        state = generator_state->args;
    }

    if (state->counter > generator_state->knobs.n4) {
        state->counter = 0;
    }

    /* Update 5-tuple values */
    generator_state->knobs.ftuple1.src_ip =
        rte_cpu_to_be_32(state->ip + state->counter);

    /* Change phase? */
    if (get_time_ns() - state->timestamp >= generator_state->knobs.n3) {
        state->phase = !state->phase;
        state->timestamp = get_time_ns();
        state->p = (!state->phase) ? generator_state->knobs.n1
                                   : generator_state->knobs.n2;
    }

    /* Choose path by probability */
    /* Output is a pointer to the 5-tuple */
    if (queue_idx < state->p) {
    	*out = &generator_state->knobs.ftuple1;
    } else {
    	*out = &generator_state->knobs.ftuple2;
    }

    /* Update counter */
    state->counter++;

    /* Output is a pointer to the 5-tuple */
    *out = &generator_state->knobs.ftuple1;

    generator_state->args = state;
    generator_state->status = GENERATOR_VALID;
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

void
generator_policy_pcap(uint64_t pkt_num,
                      uint16_t queue_idx,
                      uint16_t queue_total,
                      struct generator_state *generator_state,
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
        char error[PCAP_ERRBUF_SIZE];
        state->p = pcap_open_offline(generator_state->knobs.file1, error);
        if (!state->p) {
            printf("Cannot open PCAP file: %s\n", error);
            exit(EXIT_FAILURE);
        }
    }
    /* Get state from args */
    else {
        state = generator_state->args;
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
        generator_state->status = GENERATOR_TRY_AGAIN;
    } else {
        /* Return a pointer to raw packet */
        *out = &state->raw;
        generator_state->status = GENERATOR_VALID;
    }

    generator_state->args = state;
}

void
generator_policy_mapping(uint64_t pkt_num,
                         uint16_t queue_idx,
                         uint16_t queue_total,
                         struct generator_state *generator_state,
                         void **out)
{
    /* Thread specific state */
    struct {
        struct trace_mapping *trace_mapping;
        struct raw_packet raw_packet;
    } *state;
    int retval;

    /* First packet, parse initial args, set state */
    if (!pkt_num) {
        /* Memory allocation per queue (core) */
        state = xmalloc(sizeof(*state));
        memset(state, 0, sizeof(*state));

        /* Initialize values */
        state->trace_mapping =
            (struct trace_mapping*)generator_state->knobs.args;
        state->raw_packet.size = PACKET_SIZE;
    }
    /* Get state from args */
    else {
        state = generator_state->args;
    }

    /* Get next packet */
    retval = trace_mapping_get_next(state->trace_mapping,
                                    (void**)&state->raw_packet.bytes,
                                    queue_idx);

    /* No new packet, try again */
    if (retval == TRACE_MAPPING_TRY_AGAIN) {
        *out = NULL;
        generator_state->status = GENERATOR_TRY_AGAIN;
    }
    /* No new packet, end of locality */
    else if (retval == TRACE_MAPPING_END) {
        *out = NULL;
         generator_state->status = GENERATOR_END;
    }
    /* Output is a raw packet */
    else {
        *out = &state->raw_packet;
        generator_state->status = GENERATOR_VALID;
    }

    generator_state->args = state;
}

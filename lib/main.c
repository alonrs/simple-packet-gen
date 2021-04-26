#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>
#include <signal.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <rte_ethdev.h>
#include <rte_spinlock.h>

#include "config.h"
#include "common.h"
#include "arguments.h"
#include "vector.h"
#include "packet.h"
#include "device.h"
#include "generator.h"
#include "rate-limiter.h"

#define FTUPLE_DEF_VAL "6, 192.168.0.1, 10.0.0.1, 100, 200"

static int lcore_tx_worker(void *arg);
static int lcore_rx_worker(void *arg);

enum { MAX_EAL_ARGS = 64 };

/* Passed to worker threads */
struct worker_settings {
    generator_policy_func_t generator; /* Packet generator */
    generator_mode_t generator_mode;
    void *args;                        /* Generator custom arguments */
    bool collect_latency_stats;
    uint16_t tx_leader_core_id;
    uint16_t rx_leader_core_id;
    uint16_t queue_index;
    uint16_t tx_queue_num;
    uint16_t rx_queue_num;
    int time_limit;
    int rate_limit;
};

/* Application arguments and help.
 * Format: name, required, is-boolean, default, help */
static struct arguments app_args[] = {
/* Name            R  B  Def     Help */
{"tx",             1, 0, "0",    "TX port number."},
{"rx" ,            1, 0, "0",    "RX port number."},
{"eal",            0, 0, "",     "DPDK EAL arguments."},
{"txq",            0, 0, "4",    "Number of TX queues."},
{"rxq",            0, 0, "4",    "Number of RX queues."},
{"tx-descs",       0, 0, "256",  "Number of TX descs."},
{"rx-descs",       0, 0, "256",  "Number of RX descs."},

/* Output files */
{"lat-file",       0, 0, NULL,   "Out filename for latency per packet values."},

/* Limiters */
{"time-limit",     0, 0, "0",    "Stop application after VALUE seconds"},
{"rate-limit",     0, 0, "0",    "If VALUE>0, limites TX rate in Kpps."},

/* Statistics */
{"xstats",         0, 1, NULL,   "Show port xstats at the end."},
{"hide-zeros",     0, 1, NULL,   "(xstats) Hide zero values."},

/* Superspreader / nflows policies */
{"p-superspreader",0, 1, NULL,   "(Policy) Generate packets using a "
                                 "superspreader policy, continuously "
                                 "increaseing dst-ip and dst-port."},
{"p-nflows",       0, 1, NULL,   "(Policy) Generate packets s.t each packet "
                                 "is sent with a different src-ip and dst-ip."},
{"flows",          0, 0, "100",  "(Superspreader / nflows policies) "
                                 "Number of unique to generate."},
{"5tuple",         0, 0, FTUPLE_DEF_VAL,
                                 "(Superspreader / nflows policies) "
                                 "Base 5-tuple for flow generation."},

/* PCAP policy */
{"p-pcap",         0, 1, NULL,   "(Policy) Read packets from a PCAP file."},
{"pcap-name",      0, 0, "",     "(Pcap policy) name of PCAP file to play."},
{NULL,             0, 0, NULL,   "Simple DPDK client."}
};

/* Atomic messages accross cores, each a single cache line */
MESSAGE_T(bool, running);
MESSAGE_T(long, tx_counter);
MESSAGE_T(long, rx_counter);
MESSAGE_T(long, rx_err_counter);

rte_spinlock_t latency_lock;
atomic_long latency_counter;
atomic_long latency_total;
static struct vector *latency_vector;

static struct port_settings tx_settings;
static struct port_settings rx_settings;
static struct worker_settings worker_settings;

/* Force quit on SIGINT or SIGTERM */
static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("Signal %d received, preparing to exit...\n", signum);
        atomic_store(&running.val, false);
    }
}

/* Get "ssnf_args" from user */
static struct ssnf_args
parse_ssnf_args()
{
    struct ssnf_args ssnf_args;
    const char *ftuple_args;

    ssnf_args.flow_num = ARG_INTEGER(app_args, "flows", 100);
    ftuple_args = ARG_STRING(app_args, "5tuple", FTUPLE_DEF_VAL);
    if (ftuple_parse(&ssnf_args.base, ftuple_args)) {
        printf("Error parsing 5-tuple string \"%s\". Using default.\n",
               ftuple_args);
    }
    return ssnf_args;
}

/* Parse application arguments */
static void
initialize_settings()
{
    /* Initialize port settings */
    memset(&tx_settings, 0, sizeof(tx_settings));
    memset(&rx_settings, 0, sizeof(rx_settings));
    tx_settings.port_id = ARG_INTEGER(app_args, "tx", 0);
    tx_settings.tx_queues = ARG_INTEGER(app_args, "txq", 4);
    tx_settings.tx_descs = ARG_INTEGER(app_args, "tx-descs", 256);
    tx_settings.rx_queues = 1;
    tx_settings.rx_descs = 64;
    rx_settings.port_id = ARG_INTEGER(app_args, "rx", 1);
    rx_settings.rx_queues = ARG_INTEGER(app_args, "rxq", 4);
    rx_settings.rx_descs = ARG_INTEGER(app_args, "rx-descs", 256);
    rx_settings.tx_queues = 1;
    rx_settings.tx_descs = 64;
    worker_settings.tx_queue_num = tx_settings.tx_queues;
    worker_settings.rx_queue_num = rx_settings.rx_queues;
    worker_settings.collect_latency_stats = ARG_BOOL(app_args, "lat-file", 0);
    worker_settings.time_limit = ARG_INTEGER(app_args, "time-limit", 0);
    worker_settings.rate_limit = ARG_INTEGER(app_args, "rate-limit", 0);

    /* Set generator policy */
    policy_t policy = POLICY_UNDEFINED;
    if (ARG_BOOL(app_args, "p-superspreader", 0)) {
        policy = POLICY_SUPERSPREADER;
    } else if (ARG_BOOL(app_args, "p-nflows", 0)) {
        policy = POLICY_NFLOWS;
    } else if (ARG_BOOL(app_args, "p-pcap", 0)) {
        policy = POLICY_PCAP;
    } else {
        printf("Packet generation policy was not given. Using default. \n");
    }

    switch (policy) {
    case POLICY_NFLOWS: {
        struct ssnf_args ssnf_args = parse_ssnf_args();
        printf("Using n-flows policy with %u flows "
               "and 5-tuple ", ssnf_args.flow_num);
        ftuple_print(stdout, &ssnf_args.base);
        printf("\n");
        worker_settings.generator = generator_policy_nflows;
        worker_settings.generator_mode = GENERATOR_OUT_FTUPLE;
        worker_settings.args = alloc_void_arg_bytes(&ssnf_args,
                                                    sizeof(ssnf_args));
        break;
    }
    case POLICY_PCAP: {
        const char *pcap_fname = ARG_STRING(app_args, "pcap-name", "");
        printf("Using PCAP policy. reading PCAP from \"%s\"\n", pcap_fname);
        worker_settings.generator = generator_policy_pcap;
        worker_settings.generator_mode = GENERATOR_OUT_RAW;
        worker_settings.args = (void*)pcap_fname;
        break;
    }
    case POLICY_SUPERSPREADER:
    default: {
        struct ssnf_args ssnf_args = parse_ssnf_args();
        printf("Using superspreader policy with %u flows "
               "and 5-tuple ", ssnf_args.flow_num);
        ftuple_print(stdout, &ssnf_args.base);
        printf("\n");
        worker_settings.generator = generator_policy_superspreader;
        worker_settings.generator_mode = GENERATOR_OUT_FTUPLE;
        worker_settings.args = alloc_void_arg_bytes(&ssnf_args,
                                                    sizeof(ssnf_args));
        break;
    }}
}

/* Initialzie DPDK from EAL arguments */
static void
initialize_dpdk()
{
    const char *args;
    char *args_mod;
    char *argv[MAX_EAL_ARGS];
    char *cur;
    int argc;

    args = ARG_STRING(app_args, "eal", "");
    args_mod = xmalloc(sizeof(char)*(strlen(args)+1));

    strcpy(args_mod, args);
    argc = 1;
    argv[0] = "";
    cur = strtok(args_mod, " ");

    while (cur && argc < MAX_EAL_ARGS-1) {
        argv[argc++] = cur;
        cur = strtok(0, " ");
    }

    /* Print EAL arguments */
    printf("EAL arguments: ");
    for (int i=1; i<argc; i++) {
        printf("[%s] ", argv[i]);
    }
    printf("\n");

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    free(args_mod);
}

/* Save latency file */
static void
save_latency_file()
{
    const char *filename;
    FILE *file;

    filename = ARG_STRING(app_args, "lat-file", NULL);
    if (!filename) {
        return;
    }

    file = fopen(filename, "w");
    if (!file) {
        printf("Error: cannot open \"%s\" for writing. \n", filename);
        return;
    }

    printf("Saving %lu collected latency items in \"%s\"... \n",
           vector_size(latency_vector), filename);

    /* For each value in latency vector */
    uint64_t val;
    VECTOR_FOR_EACH(latency_vector, val, uint64_t) {
        fprintf(file, "%lu\n", val);
    }

    fclose(file);
}

int
main(int argc, char *argv[])
{
    uint32_t nb_ports;
    uint32_t lcore_id;
    uint32_t socket;
    uint16_t tx_workers;
    uint16_t rx_workers;

    /* Parse application argumnets, initialize */
    arg_parse(argc, argv, app_args);
    initialize_settings(argc, argv);
    initialize_dpdk();

    /* Initialize signal handler */
    atomic_init(&running.val, true);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize counters, locks */
    atomic_init(&tx_counter.val, 0);
    atomic_init(&rx_counter.val, 0);
    atomic_init(&rx_err_counter.val, 0);
    atomic_init(&latency_counter, 0);
    atomic_init(&latency_total, 0);
    rte_spinlock_init(&latency_lock);
    latency_vector = vector_init(sizeof(struct vector*));

    /* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 2) {
        rte_exit(EXIT_FAILURE, "Error: number of ports is not 2. "
                 "Use the EAL -a option to filter PCI addresses.\n");
    } else if (nb_ports > 2) {
        printf("Warning: got more than two ports; using first two.\n");
    }

    /* Initialize ports */
    if (port_init(&tx_settings)) {
        rte_exit(EXIT_FAILURE,
                 "Cannot init port %" PRIu16 "\n",
                 tx_settings.port_id);
    }
    if (port_init(&rx_settings)) {
        rte_exit(EXIT_FAILURE,
                 "Cannot init port %" PRIu16 "\n",
                 rx_settings.port_id);
    }

    tx_workers=0;
    rx_workers=0;

    /* Am I TX or RX worker */
    if (rte_socket_id() == tx_settings.socket) {
        tx_workers++;
        worker_settings.tx_leader_core_id = rte_lcore_id();
    } else {
        rx_workers++;
        worker_settings.rx_leader_core_id = rte_lcore_id();
    }

    /* Start workers on all cores */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        socket = rte_lcore_to_socket_id(lcore_id);
        if ((socket == tx_settings.socket) &&
            (tx_workers < tx_settings.tx_queues)) {
            printf ("Starting TX worker on core %d\n", lcore_id);
            if (tx_workers == 0) {
                worker_settings.tx_leader_core_id = lcore_id;
            }
            worker_settings.queue_index = tx_workers;
            rte_eal_remote_launch(lcore_tx_worker,
                                  alloc_void_arg_bytes(&worker_settings,
                                                       sizeof(worker_settings)),
                                  lcore_id);
            tx_workers++;
        } else if ((socket == rx_settings.socket) &&
                   (rx_workers < rx_settings.rx_queues)) {
            printf ("Starting RX worker on core %d\n", lcore_id);
            if (rx_workers == 0) {
                worker_settings.rx_leader_core_id = lcore_id;
            }
            worker_settings.queue_index = rx_workers;
            rte_eal_remote_launch(lcore_rx_worker,
                                  alloc_void_arg_bytes(&worker_settings,
                                                       sizeof(worker_settings)),
                                  lcore_id);
            rx_workers++;
        }
    }

    /* Am I TX or RX worker */
    worker_settings.queue_index = 0;
    if (rte_socket_id() == tx_settings.socket) {
        printf ("Starting TX worker on core %d\n", rte_lcore_id());
        lcore_tx_worker(alloc_void_arg_bytes(&worker_settings,
                                             sizeof(worker_settings)));
    } else {
        printf ("Starting RX worker on core %d\n", rte_lcore_id());
        lcore_rx_worker(alloc_void_arg_bytes(&worker_settings,
                                             sizeof(worker_settings)));
    }

    /* Wait for all cores. Will get here only after signal. */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        rte_eal_wait_lcore(lcore_id);
    }

    /* Show xstats */
    bool xstats = ARG_BOOL(app_args, "xstats", false);
    bool hide_zeros = ARG_BOOL(app_args, "hide-zeros", false);
    if (xstats) {
        port_xstats_display(tx_settings.port_id, hide_zeros);
        port_xstats_display(rx_settings.port_id, hide_zeros);
    }

    /* Save latency file */
    save_latency_file();

    return 0;
}

/* Generate a packet batch acording to "worker_settings", fill "rte_mbufs".
 * The generator state "gen_state" is both read and updated.
 * Method is inline for compiler optimizations with "batch_size" */
static inline void
tx_generate_batch(struct rte_mbuf **rte_mbufs,
                  struct worker_settings *worker_settings,
                  void **gen_state,
                  uint64_t *packet_counter,
                  const int batch_size)
{
    void *gen_data;

    /* Initiate state */
    if (!*packet_counter) {
        *gen_state = worker_settings->args;
    }

    /* Generate packet batch based on the 5-tuple */
    for (int i=0; i<batch_size; i++) {
        *gen_state = worker_settings->generator(*packet_counter,
                                                worker_settings->queue_index,
                                                worker_settings->tx_queue_num,
                                                *gen_state,
                                                &gen_data);

        /* Fill "rte_mbufs[i]" with data according to the generator mode */
        if (worker_settings->generator_mode == GENERATOR_OUT_FTUPLE) {
            generate_packet_ftuple(rte_mbufs[i],
                                   &tx_settings.mac_addr,
                                   &rx_settings.mac_addr,
                                   PACKET_SIZE,
                                   (struct ftuple*)gen_data,
                                   (worker_settings->queue_index==0) &&
                                   DEBUG_PRINT_PACKETS);
        } else if (worker_settings->generator_mode == GENERATOR_OUT_RAW) {
            generate_packet_raw(rte_mbufs[i],
                                ((struct raw_packet*)gen_data)->bytes,
                                ((struct raw_packet*)gen_data)->size);
        }
        (*packet_counter)++;
    }
}

/* Sends "batch_size" packet from "rte_mbufs" according to "worker_settings".
 * Method is inline for compiler optimizations with "batch_size" */
static inline void
tx_send_batch(struct rte_mbuf **rte_mbufs,
              struct worker_settings *worker_settings,
              const int batch_size)
{
    uint16_t retval;

    /* Send packets */
    retval = rte_eth_tx_burst(tx_settings.port_id,
                              worker_settings->queue_index,
                              rte_mbufs,
                              batch_size);

    /* Update TX counter */
    if (retval > 0) {
        atomic_fetch_add(&tx_counter.val, retval);
    }
}

/* Prints TX counter to stdout, only from the TX leader core */
static void
tx_show_counter(const int socket,
                const int core,
                const struct worker_settings *worker_settings,
                int *sec_counter)
{
    static uint64_t last_timestamp = 0;
    double diff_ns;
    double mpps;
    long counter;

    /* Leader prints to screen */
    if (core != worker_settings->tx_leader_core_id) {
        return;
    }

    if (!last_timestamp) {
        last_timestamp = get_time_ns();
    }

    diff_ns = get_time_ns() - last_timestamp;
    if (diff_ns < 1e9) {
        return;
    }

    counter = atomic_exchange(&tx_counter.val, 0);
    mpps = (double)counter/1e6/(diff_ns/1e9);

    printf("TX %.4lf Mpps\n", mpps);

    last_timestamp = get_time_ns();
    (*sec_counter)++;

    /* Time limit */
    if (worker_settings->time_limit &&
        (*sec_counter) >= worker_settings->time_limit) {
        printf("Time limit has reached \n");
        atomic_store(&running.val, false);
    }
}

/* Allocate mbufs for TX */
static inline void
tx_allocate_mbufs(int socket,
                  struct rte_mbuf **rte_mbufs,
                  const int batch_size)
{
    struct rte_mempool *rte_mempool;
    uint16_t retval;

    /* Allocate memory */
    rte_mempool = create_mempool(socket,
                                 DEVICE_MEMPOOL_DEF_SIZE,
                                 tx_settings.tx_descs*2);
    retval = rte_pktmbuf_alloc_bulk(rte_mempool, rte_mbufs, batch_size);
    if (retval) {
        rte_exit(EXIT_FAILURE, "Failed to allocate mbuf \n");
    }
}

/* Receive a "batch_size" incoming packets into "rte_mbufs" according to the
 * settings defined in "worker_settings", and update the global counters.
 * Returns the number of received packets.
 * The method is inline for compiler optimizations. */
static inline int
rx_receive_batch(const struct worker_settings *worker_settings,
                 struct rte_mbuf **rte_mbufs,
                 const int batch_size)
{
    uint16_t packets;

    packets = rte_eth_rx_burst(rx_settings.port_id,
                               worker_settings->queue_index,
                               rte_mbufs,
                               batch_size);

    /* Update RX counters */
    if (packets > 0) {
       atomic_fetch_add(&rx_counter.val, packets);
    }

    return packets;
}

/* Reads "num_packets" from "rte_mbufs" according to the settings defined in
 * "worker_settings", and update global RX counters. In case the latencies
 * need to be collected, they will be pushed into "vector" every "gap" packets.
 */
static void
rx_parse_packets(const struct worker_settings *worker_settings,
                 struct rte_mbuf **rte_mbufs,
                 const int num_packets,
                 const int gap,
                 struct vector *vector)
{
    uint64_t timestamp;
    uint64_t current_ns;
    uint64_t latency_ns;
    uint64_t diff_total;
    int retval;
    int err_counter;
    int diff_counter;

    current_ns = get_time_ns();
    err_counter = 0;
    diff_counter = 0;
    diff_total = 0;

    /* Read incoming packets, uppdate latency vector and global counters */
    for (int i=0; i<num_packets; i++) {
        retval = read_packet(rte_mbufs[i], &timestamp);
        if (retval) {
            err_counter++;
            continue;
        }

        /* Update local stats */
        latency_ns = current_ns - timestamp;
        diff_total += latency_ns;
        diff_counter++;

        if (!worker_settings->collect_latency_stats) {
            continue;
        }

        /* Update local vector every LATENCY_COLLECTOR_GAP packets */
        if (i%gap==0) {
            vector_push(vector, &latency_ns);
        }
    }

    /* Update global error counter */
    if (err_counter > 0) {
        atomic_fetch_add(&rx_err_counter.val, err_counter);
    }

    /* Update latency counters */
    if (diff_counter > 0) {
        rte_spinlock_lock(&latency_lock);
        atomic_fetch_add(&latency_total, diff_total);
        atomic_fetch_add(&latency_counter, diff_counter);
        rte_spinlock_unlock(&latency_lock);
    }
}

/* Free the mbufs memory */
static inline void
rx_free_memory(struct rte_mbuf **rte_mbufs,
               const int num_packets)
{
    for (int i=0; i<num_packets; i++) {
        rte_pktmbuf_free(rte_mbufs[i]);
    }
}

/* Prints RX counter to stdout, only from the RX leader core */
static void
rx_show_counter(const int core,
                const struct worker_settings *worker_settings)
{
    static uint64_t last_timestamp = 0;
    double diff_ns;
    double mpps;
    double avg_latency_usec;
    long counter;
    long err_counter;
    long diff_total;
    long diff_counter;

    /* Leader prints to screen */
    if (core != worker_settings->rx_leader_core_id) {
        return;
    }

    if (!last_timestamp) {
        last_timestamp = get_time_ns();
    }

    diff_ns = get_time_ns() - last_timestamp;
    if (diff_ns < 1e9) {
        return;
    }

    counter = atomic_exchange(&rx_counter.val, 0);
    mpps = (double)counter/1e6/(diff_ns/1e9);
    err_counter = atomic_exchange(&rx_err_counter.val, 0);

    /* Calc avg latency */
    rte_spinlock_lock(&latency_lock);
    diff_total = atomic_exchange(&latency_total, 0);
    diff_counter = atomic_exchange(&latency_counter, 0);
    avg_latency_usec = (diff_counter == 0) ? 0 :
            (double)diff_total / diff_counter / 1e3;
    rte_spinlock_unlock(&latency_lock);

    printf("RX %.4lf Mpps, errors: %lu, avg. latency %.1lf usec\n",
           mpps, err_counter, avg_latency_usec);
    last_timestamp = get_time_ns();
}

/* Main TX worker */
static int
lcore_tx_worker(void *arg)
{
    struct worker_settings worker_settings;
    struct rte_mbuf *rte_mbufs[BATCH_SIZE];
    struct rate_limiter rate_limiter;
    uint64_t pkt_counter;
    int socket, core;
    int sec_counter;
    void *gen_state;

    socket = rte_socket_id();
    core = rte_lcore_id();
    pkt_counter = 0;
    sec_counter = 0;
    gen_state = NULL;

    get_void_arg_bytes(&worker_settings,
                       arg,
                       sizeof(worker_settings),
                       true);

    rate_limiter_init(&rate_limiter,
                      worker_settings.rate_limit,
                      BATCH_SIZE,
                      worker_settings.tx_queue_num);

    tx_allocate_mbufs(socket, rte_mbufs, BATCH_SIZE);

    while(running.val) {
        tx_generate_batch(rte_mbufs,
                          &worker_settings,
                          &gen_state,
                          &pkt_counter,
                          BATCH_SIZE);

        tx_send_batch(rte_mbufs, &worker_settings, BATCH_SIZE);

        tx_show_counter(socket,
                        core,
                        &worker_settings,
                        &sec_counter);

        rate_limiter_wait(&rate_limiter);
    }

    return 0;
}

/* Main RX worker */
static int
lcore_rx_worker(void *arg)
{
    struct rte_mbuf *rte_mbufs[BATCH_SIZE];
    struct worker_settings worker_settings;
    struct vector *vector;
    int packets;
    int core;

    get_void_arg_bytes(&worker_settings,
                       arg,
                       sizeof(worker_settings),
                       true);
    core = rte_lcore_id();
    /* Local vector for latency values */
    vector = vector_init(sizeof(uint64_t));

    while(running.val) {
        /* Get a batch of packets */
        packets = rx_receive_batch(&worker_settings,
                                   rte_mbufs,
                                   BATCH_SIZE);

        /* Parse packets, update latency vector */
        rx_parse_packets(&worker_settings,
                        rte_mbufs,
                        packets,
                        LATENCY_COLLECTOR_GAP,
                        vector);

        /* Free allocated memory */
        rx_free_memory(rte_mbufs, packets);

        /* Leader prints to screen */
        rx_show_counter(core,
                        &worker_settings);
    }

    /* Push values from local vector into the global vector */
    uint64_t val;
    VECTOR_FOR_EACH(vector, val, uint64_t) {
        vector_push(latency_vector, &val);
    }
    vector_destroy(vector);

    return 0;
}

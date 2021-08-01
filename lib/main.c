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
#include <unistd.h>

#include "libcommon/lib/arguments.h"
#include "libcommon/lib/vector.h"
#include "libcommon/lib/map.h"
#include "libcommon/lib/thread-sync.h"
#include "config.h"
#include "common.h"
#include "packet.h"
#include "device.h"
#include "generator.h"
#include "rate-limiter.h"
#include "trace-mapping.h"

#define FTUPLE_DEF_1 "6, 101.0.0.0, 100.0.0.1, 1000,1000"
#define FTUPLE_DEF_2 "6, 101.0.0.0, 100.0.0.1, 1000,1000"
#define MAP_INITIAL_SIZE 512

static int lcore_tx_worker(void *arg);
static int lcore_rx_worker(void *arg);

enum { MAX_EAL_ARGS = 64 };

enum {
    GENERATOR_STATUS_OKAY = 0,
    GENERATOR_STATUS_END = 1
};

/* Passed to worker threads */
struct worker_settings {
    generator_policy_func_t generator;      /* Packet generator */
    generator_mode_t generator_mode;        /* RAW or 5-tuples */
    double rate_limit;                      /* Zero stands for no limit */
    struct generator_state generator_state; /* Generator state */
    uint64_t packet_limit;             /* Zero stands for no limit */
    int time_limit;                    /* Zero stands for no limit */
    int tx_limit;                      /* Zero stands for no limit */
    int rate_stats;                    /* Report counters each X ns */
    bool pingpong;                     /* See arguments help for pingpong */
    bool collect_latency_stats;        /* Store latency results in vector */
    bool collect_ftuple_stats;         /* Store 5-tuple results in map */
    bool collect_srcip_stats;          /* Store srcip results in map */
    bool compute_checksum;             /* Compute checksum for 5-tuples */
    uint16_t tx_leader_core_id;
    uint16_t rx_leader_core_id;
    uint16_t queue_index;
    uint16_t tx_queue_num;
    uint16_t rx_queue_num;
    uint16_t batch_size;
    uint16_t stats_gap;
    char unit_stats[16];               /* Unit for printing to screen */
};

/* Elements in 5-tuple stats */
struct ftuple_stat_node {
    struct map_node node;
    struct ftuple ftuple;
    uint64_t counter;
};

/* Elements in srcip stats */
struct srcip_stat_node {
    struct map_node node;
    uint32_t srcip;
    uint64_t counter_tx;
    uint64_t counter_rx;
};

/* Application arguments and help.
 * Format: name, required, is-boolean, default, help */
static struct arguments app_args[] = {
/* Name            R  B  Def     Help */
{"tx",             1, 0, "0",    "(Config) TX port number."},
{"rx" ,            1, 0, "0",    "(Config) RX port number."},
{"eal",            0, 0, "",     "(Config) DPDK EAL arguments."},
{"txq",            0, 0, "4",    "(Config) Number of TX queues."},
{"rxq",            0, 0, "4",    "(Config) Number of RX queues."},
{"tx-descs",       0, 0, "256",  "(Config) Number of TX descs."},
{"rx-descs",       0, 0, "256",  "(Config) Number of RX descs."},
{"batch-size",     0, 0, "64",   "(Config) Batch size for sending packets."},
{"skip-checksum",  0, 1, NULL,   "(Config) Do not calculate checksums."},

/* Special modes */
{"ping-pong",      0, 1, NULL,   "(Mode) Enable ping-pong mode. The TX and RX "
                                 "tasks are performed serially on the same "
                                 "core. Packets are sent one-by-one only after "
                                 "the previous sent packet is received. "
                                 "Latency is measured directly, not using "
                                 "timstamps on the packets' payloads. This "
                                 "mode uses only 1 RX/TX queue, regardless of "
                                 "'rxq' and 'txq' parameters."},
{"signal",         0, 0, "0",    "On every state change of the packet "
                                 "generator, signal SIGUSR1 to PID VALUE and "
                                 "then wait for an input"},
/* Print statistics to files, */
{"latency-stats",  0, 0, NULL,   "(Statistics) Collect latency statistics "
                                 "per 'stats-gap' packets. Save results to "
                                 "file named VALUE."},
{"5tuple-stats",   0, 0, NULL,   "(Statistics) Collect number of received "
                                 "packets per 'stats-gap' 5-tuples. Save "
                                 "results to file named VALUE."},
{"srcip-stats",    0, 0, NULL,   "(Statistics) Collect number of sent/received "
                                 "packets per src-ip. Useful for DDOS attack "
                                 "analysis. Save results to file named VALUE."},
{"rate-stats",     0, 0, "1000", "(Statistics) Print TX and RX statistics to "
                                 "stdout each VALUE msec. If VALUE==1000, "
                                 "the statistics are given as Mpps; otherwise, "
                                 "as packets per VALUE msec."},
{"stats-gap",      0, 0, "24",   "(Statistics) Controls the gap (in packets) "
                                 "between statistics measurements."},

/* Limiters */
{"tx-limit",       0, 0, "0",    "(Limiter) If VALUE>0, stops TX queues "
                                 "after VALUE seconds."},
{"time-limit",     0, 0, "0",    "(Limiter) If VALUE>0, stops application "
                                 "after VALUE seconds."},
{"packet-limit",   0, 0, "0",    "(Limiter) If VALUE>0, stops TX queues "
                                 "after VALUE packets have been sent."},
{"rate-limit",     0, 0, "0",    "(Limiter) If VALUE>0, limites TX rate to "
                                 "be approximately value kpps. VALUE can be "
                                 "a fraction."},

/* Statistics */
{"xstats",         0, 1, NULL,   "(NIC-stats) Show port xstats at the end."},
{"hide-zeros",     0, 1, NULL,   "(NIC-stats) Hide zero values with xstats."},

/* Generator policies */
{"p-superspreader",0, 1, NULL,   "(Policy) Generate packets using a "
                                 "superspreader policy. 'n1' knob controls "
                                 "the number of users (src-ips), 'n2' knob "
                                 "controls the number of unique destinations "
                                 "(dst-ips). The src-ips are divided into "
                                 "batches, s.t. each has 'n3' src-ips, "
                                 "and 'n4' packets. There are 'txq' simul"
                                 "taneous batches. '5tuple' knob controls "
                                 "the basic 5-tuple for generation packets. "
                                 "Statistics per user can be "
                                 "received using 'srcip-stats' knob."},
{"p-nflows",       0, 1, NULL,   "(Policy) Generate packets s.t each packet "
                                 "is sent with a different src-ip and dst-ip. "
                                 "'n1' knob controls the number of unique "
                                 "flows to generate. 'n2' knob controls the "
                                 "probability to change flow (between "
                                 "(0.0-1.0). '5tuple' knob controls "
                                 "the basic 5-tuple for generating packets."},
{"p-paths",        0, 1, NULL,   "(Policy) Given two 5-tuples, flip a coin "
                                 "with a given probability to decide which "
                                 "5-tuple to generate per packet. "
                                 "The probability (0.0-1.0) is changed "
                                 "every few msec (adjustable, integer) "
                                 "to be one of two adjustable values. "
                                 "'n1' knob sets the first probability. "
                                 "'n2' knob sets the second probability. "
                                 "'n3' knob controls the change frequency. "
                                 "'5tuple' knob sets the first 5-tuple. "
                                 "'5tuple2' knob sets the second 5-tuple. "},
{"p-pcap",         0, 1, NULL,   "(Policy) Read packets from a PCAP file. "
                                 "'file1' knob controls the PCAP filename. "},
{"p-mapping",      0, 1, NULL,   "(Policy) Load 5-tuple mapping from external, "
                                 "textual files. 'file1' knob controls the "
                                 "mapping filename (required). 'file2' knob "
                                 "controls the timestamp filename (optional). "
                                 "'file3' knob controls the locality filename "
                                 "(optional). 'n1' knob controls the number of "
                                 "background packet generators (set to 0 if "
                                 "the packet generation should be performed "
                                 "by the TX queues). If 'file3' knob is "
                                 "not set, the mapping would have a uniform "
                                 "locality with 'n2' knob to control the "
                                 "number of packets, and 'n3' knob to control "
                                 "the number of unique flows. 'n4' controls "
                                 "whether to use adaptive speed ('n4'=1) or "
                                 "constant speed ('n4'=0). In the adaptive "
                                 "speed setting, the inter-packet delays loaded "
                                 "from the 'timestamp' file would be doubled "
                                 "whenever the drop rate > 1%, "
                                 "otherwise they will be reduced by 1.5x."},

/* Policy knobs */
{"n1",             0, 0, "3",          "(Policy knob) 'n1' knob."},
{"n2",             0, 0, "5",          "(Policy knob) 'n2' knob."},
{"n3",             0, 0, "1",          "(Policy knob) 'n3' knob."},
{"n4",             0, 0, "1",          "(Policy knob) 'n4' knob."},
{"5tuple",         0, 0, FTUPLE_DEF_1, "(Policy knob) '5tuple' knob."},
{"5tuple2",        0, 0, FTUPLE_DEF_2, "(Policy knob) '5tuple2' knob."},
{"file1",          0, 0, NULL,         "(Policy knob) 'file1' knob."},
{"file2",          0, 0, NULL,         "(Policy knob) 'file2' knob."},
{"file3",          0, 0, NULL,         "(Policy knob) 'file3' knob."},

/* Sentinel */
{NULL,             0, 0, NULL,   "Send and receive packets using DPDK. "
                                 "Supports several packet generation policies. "
                                 "See 'generator.h' for supporting more "
                                 "generation policies."}
};

/* Atomic messages accross cores, each a single cache line */
MESSAGE_T(bool, tx_running);
MESSAGE_T(long, tx_counter);
MESSAGE_T(long, rx_counter);
MESSAGE_T(long, drop_tx_counter);
MESSAGE_T(long, drop_rx_counter);
MESSAGE_T(long, rx_err_counter);
MESSAGE_T(int, pingpong_send);

rte_spinlock_t latency_lock;
rte_spinlock_t ftuple_stats_map_lock;
rte_spinlock_t srcip_stats_map_lock;
atomic_long latency_counter;
atomic_long latency_total;
atomic_ulong pingpong_timestamp;

/* Collects statistics */
static struct vector *latency_vector;
static struct map ftuple_stats_map;
static struct map srcip_stats_map;

static struct port_settings tx_settings;
static struct port_settings rx_settings;
static struct worker_settings worker_settings;

/* Packet generation policy */
static policy_t policy;

/* Signals, states */
static pid_t signal_pid = 0;
struct thread_sync ts_signal;
enum {
    SIGNAL_RUNNING     = 0,
    SIGNAL_STOP        = 1,
    SIGNAL_PAUSE       = 2,
    SIGNAL_RESTART     = 4,
    SIGNAL_RATELIMITER = 8,
    SIGNAL_MULTIPLIER  = 16
};

/* Static method declaration */
static void register_signals();

/* Initialize atomic counters */
static void
initialize_counters()
{
    atomic_init(&tx_running.val, true);
    atomic_init(&tx_counter.val, 0);
    atomic_init(&drop_tx_counter.val, 0);
    atomic_init(&drop_rx_counter.val, 0);
    atomic_init(&rx_counter.val, 0);
    atomic_init(&rx_err_counter.val, 0);
    atomic_init(&latency_counter, 0);
    atomic_init(&latency_total, 0);
    atomic_init(&pingpong_timestamp, 0);
    atomic_init(&pingpong_send.val, 1);
}

/* Initialize signal parameters */
static void
initialize_signal_parameters()
{
    thread_sync_init(&ts_signal);
    thread_sync_set_event(&ts_signal, SIGNAL_RUNNING, 0);
}

/* Force quit */
static void
signal_sigterm(int signum)
{
    printf("\n");
    fflush(stdout);
    exit(0);
}

/* Pause on SIGINT */
static void
signal_sigint(int signum)
{
    int retval;
    int rate;
    char ans;
    char buf[256];
    char *ptr;

    signal(SIGINT, signal_sigterm);
    thread_sync_set_event(&ts_signal, SIGNAL_PAUSE, 0);
    fflush(stdout);

ask_again:
    printf("\rWhat would you wish to do? "
           "Continue [C]; Stop [S]; Reset with rate limiter [T]; "
           "Restart [R]; Echo [E]");
    if (policy == POLICY_MAPPING) {
         printf("; Set adaptive rate multiplier (0 disables adaptive) [A]");
    }
    printf(" :");
wait_for_ans:
    /* Support named pipes */
    do {
        ans = getchar();
    } while (ans == EOF);
    ans = tolower(ans);

    switch (ans) {
    case 'c':
        thread_sync_set_event(&ts_signal, SIGNAL_RUNNING, 0);
        break;
    case 's':
        thread_sync_set_event(&ts_signal, SIGNAL_STOP, 0);
        break;
    case 't':
        do {
            printf("%s", "Enter new rate in Kpps: ");
            do {
                retval = scanf("%d", &rate);
            } while (retval == EOF);
        } while (retval != 1);
        initialize_counters();
        printf("\nReset with constant TX rate of %d Kpps\n", rate);
        thread_sync_set_event(&ts_signal,
                              SIGNAL_RESTART | SIGNAL_RATELIMITER,
                              rate);
        break;
    case 'a':
        do {
            printf("%s", "Enter manual adaptive rate to start from: ");
            do {
                retval = scanf("%d", &rate);
            } while (retval == EOF);
        } while (retval != 1);
        printf("\nReset with adaptive TX rate %dX\n", rate);
        initialize_counters();
        thread_sync_set_event(&ts_signal,
                              SIGNAL_RESTART | SIGNAL_MULTIPLIER,
                              rate);
        break;
    case 'r':
        initialize_counters();
        thread_sync_set_event(&ts_signal, SIGNAL_RESTART, 0);
        break;
    case 'e':
        printf("Enter message: ");
        do {
            ptr = fgets(buf, sizeof(buf), stdin);
        } while (!ptr || buf[0] == '\n');
        printf("%s", buf);
        goto ask_again;
    case '\n':
    case '\r':
        goto wait_for_ans;
    default:
        goto ask_again;
    }

    register_signals();
}

/* Register the signals with singal_handler method */
static void
register_signals()
{
    signal(SIGINT, signal_sigint);
    signal(SIGTERM, signal_sigterm);
}

/* Packet generator state change: signal a custom PID the SIGUSR1 signal and
 * then wait for further instructions. */
static void
state_change_signal_pid() {
    int retval;
    if (!signal_pid) { 
        return;
    }
    retval = kill(signal_pid, SIGUSR1);
    if (retval == EINVAL) {
        printf("Cannot send signal to PID %d - invalid signal\n",
               signal_pid);
    } else if (retval == EPERM) {
        printf("Cannot send signal to PID %d - I don't have permissions\n",
               signal_pid);
    } else if (retval == ESRCH) {
        printf("Cannot send signal to PID %d - invalid PID\n",
               signal_pid);
    } else {
        printf("Signal sent to PID %d\n", signal_pid);
        signal_sigint(SIGINT);
    }
}

/* Get "policy_knobs" from user */
static struct policy_knobs
parse_policy_knobs()
{
    struct policy_knobs policy_knobs;
    const char *str;

    policy_knobs.n1 = ARG_DOUBLE(app_args, "n1", 3);
    policy_knobs.n2 = ARG_DOUBLE(app_args, "n2", 5);
    policy_knobs.n3 = ARG_DOUBLE(app_args, "n3", 1);
    policy_knobs.n4 = ARG_DOUBLE(app_args, "n4", 1);

    str = ARG_STRING(app_args, "5tuple", FTUPLE_DEF_1);
    if (ftuple_parse(&policy_knobs.ftuple1, str)) {
        printf("Error parsing 5-tuple string \"%s\".", str);
        exit(EXIT_FAILURE);
    }

    str = ARG_STRING(app_args, "5tuple2", FTUPLE_DEF_2);
    if (ftuple_parse(&policy_knobs.ftuple2, str)) {
        printf("Error parsing 5-tuple string \"%s\".", str);
        exit(EXIT_FAILURE);
    }

    policy_knobs.file1 = ARG_STRING(app_args, "file1", "");
    policy_knobs.file2 = ARG_STRING(app_args, "file2", "");
    policy_knobs.file3 = ARG_STRING(app_args, "file3", "");

    /* Additional arguments */
    policy_knobs.args = NULL;

    return policy_knobs;
}

/* Parse application arguments */
static void
initialize_settings()
{
    struct trace_mapping *trace_mapping;
    struct policy_knobs policy_knobs;
    bool enable_bg_threads;
    int num_workers;

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
    worker_settings.collect_latency_stats =
                                 ARG_BOOL(app_args, "latency-stats", 0);
    worker_settings.collect_ftuple_stats =
                                 ARG_BOOL(app_args, "5tuple-stats", 0);
    worker_settings.collect_srcip_stats =
                                 ARG_BOOL(app_args, "srcip-stats", 0);
    worker_settings.time_limit = ARG_INTEGER(app_args, "time-limit", 0);
    worker_settings.tx_limit = ARG_INTEGER(app_args, "tx-limit", 0);
    worker_settings.packet_limit = ARG_INTEGER(app_args, "packet-limit", 0);
    worker_settings.rate_limit = ARG_DOUBLE(app_args, "rate-limit", 0);
    worker_settings.batch_size = ARG_INTEGER(app_args, "batch-size", 64);
    worker_settings.pingpong = false;
    worker_settings.stats_gap = ARG_INTEGER(app_args, "stats-gap", 24);
    worker_settings.compute_checksum =
                                !(ARG_BOOL(app_args, "skip-checksum", 0));

    /* Check batch size is valid */
    if (worker_settings.batch_size > MAX_BATCH_SIZE) {
        printf("Batch size %hu is larger than maximum allowed (%d). "
               "Setting batch size to %d. \n",
               worker_settings.batch_size,
               MAX_BATCH_SIZE,
               MAX_BATCH_SIZE);
    }

    /* Special modes */
    signal_pid = ARG_INTEGER(app_args, "signal", 0);

    if (ARG_BOOL(app_args, "ping-pong", 0)) {
        printf("Operating in ping-pong mode\n");
        tx_settings.tx_queues = 1;
        rx_settings.rx_queues = 1;
        worker_settings.pingpong = true;
        worker_settings.batch_size = 1;
    }

    /* Set the rate of the stats in nanosec, set unit string */
    worker_settings.rate_stats = ARG_INTEGER(app_args, "rate-stats", 1000);
    printf("Printing stats to stdout every %d msec\n",
           worker_settings.rate_stats);
    if (worker_settings.rate_stats == 1000) {
        strcpy(worker_settings.unit_stats, "Mpps");
    } else {
        sprintf(worker_settings.unit_stats, "Mp / %d ms",
                worker_settings.rate_stats);
    }
    worker_settings.rate_stats *= 1e6;

    /* Set generator policy */
    policy = POLICY_UNDEFINED;
    if (ARG_BOOL(app_args, "p-superspreader", 0)) {
        policy = POLICY_SUPERSPREADER;
    } else if (ARG_BOOL(app_args, "p-nflows", 0)) {
        policy = POLICY_NFLOWS;
    } else if (ARG_BOOL(app_args, "p-paths", 0)) {
        policy = POLICY_PATHS;
    } else if (ARG_BOOL(app_args, "p-pcap", 0)) {
        policy = POLICY_PCAP;
    } else if (ARG_BOOL(app_args, "p-mapping", 0)) {
        policy = POLICY_MAPPING;
    } else {
        printf("Packet generation policy was not given. Using default. \n");
    }

    /* Set the policy knobs */
    policy_knobs = parse_policy_knobs();

    switch (policy) {
    case POLICY_NFLOWS:
        printf("Using n-flows policy with %lf flows, %lf pobability, "
               "and 5-tuple ",
               policy_knobs.n1,
               policy_knobs.n2);
        ftuple_print(stdout, &policy_knobs.ftuple1);
        printf("\n");
        worker_settings.generator = generator_policy_nflows;
        worker_settings.generator_mode = GENERATOR_OUT_FTUPLE;
        break;
    case POLICY_PATHS:
        printf("Using paths policy with probabilities %lf,%lf and %lf msec "
               "frequency, with the 5-tuples ",
               policy_knobs.n1,
               policy_knobs.n2,
               policy_knobs.n3);
        ftuple_print(stdout, &policy_knobs.ftuple1);
        printf(", and ");
        ftuple_print(stdout, &policy_knobs.ftuple2);
        printf("\n");
        worker_settings.generator = generator_policy_paths;
        worker_settings.generator_mode = GENERATOR_OUT_FTUPLE;
        break;
    case POLICY_PCAP:
        printf("Using PCAP policy. reading PCAP from \"%s\"\n",
               policy_knobs.file1);
        worker_settings.generator = generator_policy_pcap;
        worker_settings.generator_mode = GENERATOR_OUT_RAW;
        break;
    case POLICY_MAPPING:
        printf("Using mapping policy.\n");

        /* Do we use background threads? */
        enable_bg_threads = policy_knobs.n1 ? true : false;
        num_workers = enable_bg_threads ?
                      policy_knobs.n1 :
                      tx_settings.tx_queues;

        trace_mapping = trace_mapping_init(policy_knobs.file1,
                                           policy_knobs.file2,
                                           policy_knobs.file3,
                                           num_workers,
                                           enable_bg_threads,
                                           policy_knobs.n2,
                                           policy_knobs.n3);
        /* Disable adaptive speed setting */
        if (policy_knobs.n4 == 0) {
            trace_mapping_set_multiplier(trace_mapping, 0);
        }
        trace_mapping_start(trace_mapping);

        policy_knobs.args = trace_mapping;
        worker_settings.generator = generator_policy_mapping;
        worker_settings.generator_mode = GENERATOR_OUT_FTUPLE;
        break;
    case POLICY_SUPERSPREADER:
    default:
        printf("Using superspreader policy with %lf users, %lf destinations, "
               "and 5-tuple ",
               policy_knobs.n1,
               policy_knobs.n2);
        ftuple_print(stdout, &policy_knobs.ftuple1);
        printf("\n");
        worker_settings.generator = generator_policy_superspreader;
        worker_settings.generator_mode = GENERATOR_OUT_FTUPLE;
        break;
    }

    memcpy(&worker_settings.generator_state.knobs,
           &policy_knobs,
           sizeof(policy_knobs));
}

/* Close objects related to arguments */
static void
finalize_settings()
{
    struct policy_knobs *knobs;
    knobs = &worker_settings.generator_state.knobs;

    switch (policy) {
    case POLICY_MAPPING:
        trace_mapping_destroy((struct trace_mapping*)knobs->args);
        break;
    default:
        break;
    }
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

/* Save latency statistics file */
static void
save_latency_statistics_file()
{
    const char *filename;
    FILE *file;

    filename = ARG_STRING(app_args, "latency-stats", NULL);
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

/* Save 5-tuple statistics file */
static void
save_ftuple_statistics_file()
{
    struct ftuple_stat_node *ftuple_stat_node;
    const char *filename;
    FILE *file;

    filename = ARG_STRING(app_args, "5tuple-stats", NULL);
    if (!filename) {
        return;
    }

    file = fopen(filename, "w");
    if (!file) {
        printf("Error: cannot open \"%s\" for writing. \n", filename);
        return;
    }

    printf("Saving %lu collected 5-tuple items in \"%s\"... \n",
           map_size(&ftuple_stats_map), filename);

    /* Go over all map elements, print to file */
    MAP_FOR_EACH(ftuple_stat_node, node, &ftuple_stats_map) {
        fprintf(file, "hash: %-11u 5-tuple: ", ftuple_stat_node->node.hash);
        ftuple_print(file, &ftuple_stat_node->ftuple);
        fprintf(file, " rx-counter: %lu\n", ftuple_stat_node->counter);
        free(ftuple_stat_node);
    }
    map_destroy(&ftuple_stats_map);

    fclose(file);
}

/* Save src-ip statistics file */
static void
save_srcip_statistics_file()
{
    struct srcip_stat_node *srcip_stat_node;
    const char *filename;
    uint32_t src_ip_cpu;
    FILE *file;

    filename = ARG_STRING(app_args, "srcip-stats", NULL);
    if (!filename) {
        return;
    }

    file = fopen(filename, "w");
    if (!file) {
        printf("Error: cannot open \"%s\" for writing. \n", filename);
        return;
    }

    printf("Saving %lu collected srcip items in \"%s\"... \n",
           map_size(&srcip_stats_map), filename);

    /* Go over all map elements, print to file */
    MAP_FOR_EACH(srcip_stat_node, node, &srcip_stats_map) {
        src_ip_cpu = rte_be_to_cpu_32(srcip_stat_node->srcip);
        fprintf(file, "hash: %-11u ",
                srcip_stat_node->node.hash);
        fprintf(file, "src-ip: %d.%d.%d.%d ",
                src_ip_cpu >> 24 & 0xFF,
                src_ip_cpu >> 16 & 0xFF,
                src_ip_cpu >> 8  & 0xFF,
                src_ip_cpu & 0xFF);
        fprintf(file, " tx: %lu rx: %lu rx-percent: %.3lf %%\n",
                srcip_stat_node->counter_tx,
                srcip_stat_node->counter_rx,
                (double)srcip_stat_node->counter_rx /
                        srcip_stat_node->counter_tx * 100);
        free(srcip_stat_node);
    }
    map_destroy(&srcip_stats_map);

    fclose(file);
}

/* Collect 5-tuple statistics, called by RX workers */
static void
stats_collect_ftuple(struct map *ftuple_stats, struct ftuple *ftuple, int val)
{
    struct ftuple_stat_node *ftuple_stat_node;
    uint32_t hash;

    hash = ftuple_hash(ftuple);

    /* If node with 5-tuple exists, update counter */
    MAP_FOR_EACH_WITH_HASH(ftuple_stat_node, node, hash, ftuple_stats) {
        if (ftuple_compare(&ftuple_stat_node->ftuple, ftuple)) {
            ftuple_stat_node->counter+=val;
            return;
        }
    }

    /* Stat was not found, insert new element to map */
    ftuple_stat_node = xmalloc(sizeof(*ftuple_stat_node));
    ftuple_stat_node->ftuple = *ftuple;
    ftuple_stat_node->counter = val;
    map_insert(ftuple_stats, &ftuple_stat_node->node, hash);
}

/* Collect srcip statistics, called by TX/RX workers */
static void
stats_collect_srcip(struct map *srcip_stats,
                    uint32_t src_ip,
                    uint32_t tx_val,
                    uint32_t rx_val)
{
    struct srcip_stat_node *srcip_stat_node;
    uint32_t hash;

    hash = hash_int(src_ip, 0);

    /* If node with 5-tuple exists, update counter */
    MAP_FOR_EACH_WITH_HASH(srcip_stat_node, node, hash, srcip_stats) {
        if (srcip_stat_node->srcip == src_ip) {
            srcip_stat_node->counter_rx += rx_val;
            srcip_stat_node->counter_tx += tx_val;
            return;
        }
    }

    /* Stat was not found, insert new element to map */
    srcip_stat_node = xmalloc(sizeof(*srcip_stat_node));
    srcip_stat_node->srcip = src_ip;
    srcip_stat_node->counter_rx = rx_val;
    srcip_stat_node->counter_tx = tx_val;
    map_insert(srcip_stats, &srcip_stat_node->node, hash);
}

static void
stats_fill_latency_vector(struct worker_settings *worker_settings,
                          struct vector *latency_stats_local)
{
    if (!worker_settings->collect_latency_stats) {
        return;
    }
    printf("RX queue %d updating global latency statistics "
           "with %ld items... \n",
            worker_settings->queue_index,
            vector_size(latency_stats_local));
    uint64_t val;
    VECTOR_FOR_EACH(latency_stats_local, val, uint64_t) {
        vector_push(latency_vector, &val);
    }
}

static void
stats_fill_ftuple_map(struct worker_settings *worker_settings,
                      struct map *ftuple_stats_local)
{
    struct ftuple_stat_node *ftuple_stat_node;
    if (!worker_settings->collect_ftuple_stats) {
        return;
    }

    printf("RX queue %d updating global 5-tuple statistics "
           "with %ld items... \n",
           worker_settings->queue_index,
           map_size(ftuple_stats_local));

    rte_spinlock_lock(&ftuple_stats_map_lock);
    MAP_FOR_EACH(ftuple_stat_node, node, ftuple_stats_local) {
        stats_collect_ftuple(&ftuple_stats_map,
                             &ftuple_stat_node->ftuple,
                             ftuple_stat_node->counter);
        free(ftuple_stat_node);
    }
    rte_spinlock_unlock(&ftuple_stats_map_lock);
}

static void
stats_fill_srcip_map(struct worker_settings *worker_settings,
                     struct map *srcip_stats_local,
                     bool is_tx)
{
    struct srcip_stat_node *srcip_stat_node;
    if (!worker_settings->collect_srcip_stats) {
        return;
    }

    printf("%s queue %d updating global src-ip statistics "
           "with %ld items... \n",
           is_tx ? "TX" : "RX",
           worker_settings->queue_index,
           map_size(srcip_stats_local));

    rte_spinlock_lock(&srcip_stats_map_lock);
    MAP_FOR_EACH(srcip_stat_node, node, srcip_stats_local) {
        stats_collect_srcip(&srcip_stats_map,
                            srcip_stat_node->srcip,
                            srcip_stat_node->counter_tx,
                            srcip_stat_node->counter_rx);
        free(srcip_stat_node);
    }
    rte_spinlock_unlock(&srcip_stats_map_lock);
}

/* Starts lcore workers. Normal operation mode */
static void
workers_start_normal()
{
    uint32_t lcore_id;
    uint32_t socket;
    uint16_t tx_workers;
    uint16_t rx_workers;

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

    state_change_signal_pid();

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
}

int
main(int argc, char *argv[])
{
    /* Parse application argumnets, initialize */
    arg_parse(argc, argv, app_args);
    initialize_settings(argc, argv);
    initialize_dpdk();

    /* Initialize signal handler */
    register_signals();

    /* Initialize counters, locks */
    initialize_counters();
    rte_spinlock_init(&latency_lock);
    rte_spinlock_init(&ftuple_stats_map_lock);
    rte_spinlock_init(&srcip_stats_map_lock);
    latency_vector = vector_init(sizeof(uint64_t));
    map_init(&ftuple_stats_map, MAP_INITIAL_SIZE);
    map_init(&srcip_stats_map, MAP_INITIAL_SIZE);

    /* Initialize signal arguments */
    initialize_signal_parameters();
    
    /* Check that there is an even number of ports to send/receive on. */
    if (rte_eth_dev_count_avail() < 2) {
        rte_exit(EXIT_FAILURE, "Error: number of ports is not 2. "
                 "Use the EAL -w option to filter PCI addresses.\n");
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

    workers_start_normal();

    /* Show xstats */
    bool xstats = ARG_BOOL(app_args, "xstats", false);
    bool hide_zeros = ARG_BOOL(app_args, "hide-zeros", false);
    if (xstats) {
        port_xstats_display(tx_settings.port_id, hide_zeros);
        port_xstats_display(rx_settings.port_id, hide_zeros);
    }

    /* Save statistics */
    save_latency_statistics_file();
    save_ftuple_statistics_file();
    save_srcip_statistics_file();

    finalize_settings();
    return 0;
}

/* Create a new array of "mbufs" to send */
static inline int
tx_allocate_mbufs(struct rte_mempool *rte_mempool,
                  struct rte_mbuf **rte_mbufs,
                  struct worker_settings *worker_settings,
                  uint16_t *num_of_free_mbufs,
                  uint64_t *packet_counter)
{
    int retval;

    /* Don't allocate mbufs as long as the last batch still valid */
    if (*num_of_free_mbufs) {
        return 0;
    }

    retval = rte_pktmbuf_alloc_bulk(rte_mempool,
                                    rte_mbufs,
                                    worker_settings->batch_size);
    if (retval) {
        return 1;
    }

    *num_of_free_mbufs = worker_settings->batch_size;
    return 0;
}

/* Generate a packet batch acording to "worker_settings", fill "rte_mbufs".
 * The generator state "gen_state" is both read and updated.
 * Method is inline for compiler optimizations with "batch_size".
 * Returns values from GENERATOR_STATUS enum */
static inline int
tx_generate_batch(struct rte_mbuf **rte_mbufs,
                  struct worker_settings *worker_settings,
                  uint16_t *remaining_packets,
                  uint64_t *packet_counter)
{
    void *gen_data;
    int retval;
    int num;
    int i;
    
    retval = GENERATOR_STATUS_OKAY;

    /* Don't generate new packets as long as the last batch still valid */
    if (*remaining_packets) {
        return retval;
    }

    num = worker_settings->batch_size;

    /* Generate packet batch based on the 5-tuple */
    for (i=0; i<num; i++) {
        worker_settings->generator(*packet_counter,
                                   worker_settings->queue_index,
                                   worker_settings->tx_queue_num,
                                   &worker_settings->generator_state,
                                   &gen_data);

        /* Generator has reached its limit */
        if (worker_settings->generator_state.status == GENERATOR_END) {
            retval = GENERATOR_STATUS_END;
            break;
        }

        /* No further packets available, other reasons */
        if ((!gen_data) ||
            (worker_settings->generator_state.status == GENERATOR_TRY_AGAIN)) {
            break;
        }

        /* Fill "rte_mbufs[i]" with data according to the generator mode */
        if (worker_settings->generator_mode == GENERATOR_OUT_FTUPLE) {
            packet_generate_ftuple(rte_mbufs[i],
                                   &tx_settings.mac_addr,
                                   &rx_settings.mac_addr,
                                   PACKET_SIZE,
                                   worker_settings->compute_checksum,
                                   (struct ftuple*)gen_data,
                                   (worker_settings->queue_index==0) &&
                                   DEBUG_PRINT_PACKETS);

        } else if (worker_settings->generator_mode == GENERATOR_OUT_RAW) {
            packet_generate_raw(rte_mbufs[i],
                                ((struct raw_packet*)gen_data)->bytes,
                                ((struct raw_packet*)gen_data)->size);
        }
        (*packet_counter)++;
    }

    *remaining_packets = i;
    return retval;
}

/* Sends "batch_size" packet from "rte_mbufs" according to "worker_settings".
 * Method is inline for compiler optimizations. */
static inline uint16_t
tx_send_batch(struct rte_mbuf **rte_mbufs,
              struct worker_settings *worker_settings,
              struct map *srcip_stats,
              const uint16_t packet_num)
{
    struct ftuple ftuple;
    uint64_t timestamp;
    uint16_t retval;

    /* If we're in pingpong mode, don't send packets unless we have an okay */
    if (worker_settings->pingpong && !atomic_load(&pingpong_send.val)) {
        return 0;
    }

    /* Send packets */
    retval = rte_eth_tx_burst(tx_settings.port_id,
                              worker_settings->queue_index,
                              rte_mbufs,
                              packet_num);

    /* In pingpong mode, update that we're waiting for an okay */
    if (worker_settings->pingpong) {
        atomic_store(&pingpong_send.val, 0);
        timestamp = get_time_ns();
        atomic_store(&pingpong_timestamp, timestamp);
    }

    /* Update TX counter */
    if (retval > 0) {
        atomic_fetch_add(&tx_counter.val, retval);
        atomic_fetch_add(&drop_tx_counter.val, retval);
    }

    /* Collect srcip TX statistics */
    if (worker_settings->collect_srcip_stats) {
        for (uint16_t i=0; i<retval; i++) {
            packet_read_ftuple(rte_mbufs[i], &ftuple, NULL, NULL);
            stats_collect_srcip(srcip_stats, ftuple.src_ip, 1, 0);
        }
    }

    /* Shuffle rte_mbufs s.t unsent packets are first in array */
    if (retval < packet_num) {
        for (uint16_t i=0; i<retval; i++) {
            struct rte_mbuf *sent_mbuf = rte_mbufs[i];
            int unsend_index = packet_num-retval+i;
            rte_mbufs[i] = rte_mbufs[unsend_index];
            rte_mbufs[unsend_index] = sent_mbuf;
        }
    }

    return retval;
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
    if (diff_ns < worker_settings->rate_stats) {
        return;
    }

    /* Normalize to the time interval */
    diff_ns /= worker_settings->rate_stats;

    counter = atomic_exchange(&tx_counter.val, 0);
    mpps = (double)counter/1e6/diff_ns;

    printf("TX %.4lf %s\n", mpps, worker_settings->unit_stats);
    fflush(stdout);

    last_timestamp = get_time_ns();
    (*sec_counter)++;

}

/* Returns true if the current TX queues should stop */
static inline bool
tx_event_limit(const struct worker_settings *worker_settings,
               int core_id,
               int generator_status,
               int *sec_counter,
               uint64_t *packet_counter)
{
    bool stop_tx = false;
    bool stop = false;

    if (worker_settings->time_limit &&
        *sec_counter >= worker_settings->time_limit) {
        *sec_counter = 0;
        stop = true;
    }

    if (worker_settings->tx_limit &&
        *sec_counter >= worker_settings->tx_limit) {
        *sec_counter = 0;
        printf("TX time limit has reached.\n");
        stop_tx = true;
    }

    if (worker_settings->packet_limit &&
        *packet_counter >= worker_settings->packet_limit) {
        *packet_counter = 0;
        printf("TX packet limit %lu has reached.\n",
              worker_settings->packet_limit);
        stop_tx = true;
    }

    /* Stop TX in case the generator status has reached its end */
    if (generator_status == GENERATOR_STATUS_END) {
        stop_tx = true;
    }

    /* No event change */
    if (!stop && !stop_tx) {
        return false;
    }

    /* Lead TX core signal event change */
    if (signal_pid && core_id == worker_settings->tx_leader_core_id) {
        state_change_signal_pid();
        return false;
    }
    /* No signal for event change, act automatically */
    else if (!signal_pid && stop_tx) {
        return true;
    } else if (!signal_pid && stop) {
        atomic_store(&tx_running.val, false);
        return true;
    }

    /* Don't stop locally; global falgs may still cause application to stop */
    return false;
}

/* Receive a "batch_size" incoming packets into "rte_mbufs" according to the
 * settings defined in "worker_settings", and update the global counters.
 * Returns the number of received packets.
 * The method is inline for compiler optimizations. */
static inline int
rx_receive_batch(const struct worker_settings *worker_settings,
                 struct rte_mbuf **rte_mbufs)
{
    uint16_t packets;

    packets = rte_eth_rx_burst(rx_settings.port_id,
                               worker_settings->queue_index,
                               rte_mbufs,
                               MAX_BATCH_SIZE);

    /* Update RX counters */
    if (packets > 0) {
       atomic_fetch_add(&rx_counter.val, packets);
       atomic_fetch_add(&drop_rx_counter.val, packets);
    }

    return packets;
}

/* Reads "num_packets" from "rte_mbufs" according to the settings defined in
 * "worker_settings", update global RX counters, update statistics every
 * "gap" packets */
static void
rx_parse_packets(const struct worker_settings *worker_settings,
                 struct rte_mbuf **rte_mbufs,
                 const int num_packets,
                 const int gap,
                 struct vector *latency_stats,
                 struct map *ftuple_stats,
                 struct map *srcip_stats)
{
    struct ftuple ftuple;
    uint64_t timestamp;
    uint64_t current_ns;
    uint64_t latency_ns;
    uint64_t diff_total;
    int retval;
    int err_counter;
    int diff_counter;
    char *payload;
    int size;
    int gap_valid;

    current_ns = get_time_ns();
    err_counter = 0;
    diff_counter = 0;
    diff_total = 0;
    retval = 0;

    /* Read incoming packets, uppdate latency vector and global counters */
    for (int i=0; i<num_packets; i++) {

        /* Read the packet 5-tuple */
        retval = packet_read_ftuple(rte_mbufs[i], &ftuple, &payload, &size);
        if (retval) {
            err_counter++;
            continue;
        }

        /* Try to parse timestamp from the packet */
        timestamp = packet_parse_timestamp(payload, size);
        if (worker_settings->pingpong && !timestamp) {
            timestamp = atomic_load(&pingpong_timestamp);
        }

        /* Update latency statistics (for valid timestamps)*/
        if (timestamp) {
            latency_ns = current_ns - timestamp;
            diff_total += latency_ns;
            diff_counter++;
        }

        gap_valid = (!gap) || (i%gap == 0);

        /* Collect 5-tuple statistics */
        if ((worker_settings->collect_ftuple_stats) && gap_valid) {
            stats_collect_ftuple(ftuple_stats, &ftuple, 1);
        }

        /* Collect srcip statistics */
        if (worker_settings->collect_srcip_stats) {
            stats_collect_srcip(srcip_stats, ftuple.src_ip, 0, 1);
        }

        /* Update local vector every LATENCY_COLLECTOR_GAP packets */
        if ((worker_settings->collect_latency_stats) && gap_valid) {
            vector_push(latency_stats, &latency_ns);
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

/* Sets the adaptive speed for mapping policy with adaptive speed */
static void
adaptive_speed_multiplier(const struct worker_settings *worker_settings,
                          const double drop_percent)
{
    const struct policy_knobs *knobs;
    struct trace_mapping *trace_mapping;
    int multiplier;

    knobs = &worker_settings->generator_state.knobs;
    trace_mapping = (struct trace_mapping*)knobs->args;

    if (policy != POLICY_MAPPING) {
        return;
    }

    multiplier = trace_mapping_get_multiplier(trace_mapping);

    if ((drop_percent > 1) && (multiplier < 20000)) {
        multiplier *= 2;
    } else if (multiplier > 3) {
        multiplier = multiplier / 1.5;
    }

    trace_mapping_set_multiplier(trace_mapping, multiplier);
}

static void
adaptive_speed_set(int value)
{
    const struct policy_knobs *knobs;
    struct trace_mapping *trace_mapping;

    knobs = &worker_settings.generator_state.knobs;
    trace_mapping = (struct trace_mapping*)knobs->args;

    if (policy != POLICY_MAPPING) {
        return;
    }

    trace_mapping_set_multiplier(trace_mapping, value);
}

/* Resets configuration relavent to the packet generator */
static void
reset_packet_generator(const struct worker_settings *worker_settings)
{
    const struct policy_knobs *knobs;
    struct trace_mapping *trace_mapping;

    knobs = &worker_settings->generator_state.knobs;
    trace_mapping = (struct trace_mapping*)knobs->args;

    if (policy == POLICY_MAPPING) {
        trace_mapping_reset(trace_mapping);
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
    double drop_percent;
    long counter;
    long drop_tx_cnt;
    long drop_rx_cnt;
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
    if (diff_ns < worker_settings->rate_stats) {
        return;
    }

    /* Normalize to the time interval */
    diff_ns /= worker_settings->rate_stats;

    counter = atomic_exchange(&rx_counter.val, 0);
    mpps = (double)counter/1e6/diff_ns;
    err_counter = atomic_exchange(&rx_err_counter.val, 0);

    /* Calculate drop percent, set adaptive speed settings */
    drop_tx_cnt = atomic_exchange(&drop_tx_counter.val, 0);
    drop_rx_cnt = atomic_exchange(&drop_rx_counter.val, 0);
    drop_percent = (1.0 - (double)drop_rx_cnt / drop_tx_cnt) * 100;
    adaptive_speed_multiplier(worker_settings, drop_percent);

    /* Calc avg latency */
    rte_spinlock_lock(&latency_lock);
    diff_total = atomic_exchange(&latency_total, 0);
    diff_counter = atomic_exchange(&latency_counter, 0);
    avg_latency_usec = (diff_counter == 0) ? 0 :
            (double)diff_total / diff_counter / 1e3;
    rte_spinlock_unlock(&latency_lock);

    printf("RX %.4lf %s, errors: %lu, avg. latency %.1lf usec, "
           "drops: %.3lf %%\n",
           mpps,
           worker_settings->unit_stats,
           err_counter,
           avg_latency_usec,
           drop_percent);
    fflush(stdout);
    last_timestamp = get_time_ns();
}

/* Main TX worker */
static int
lcore_tx_worker(void *arg)
{
    struct rte_mbuf *rte_mbufs[MAX_BATCH_SIZE];
    struct worker_settings worker_settings;
    uint16_t remaining_packets_to_send;
    uint16_t num_of_free_mbufs;
    struct rate_limiter rate_limiter;
    struct rte_mempool *rte_mempool;
    struct map srcip_stats_local;
    uint64_t pkt_counter;
    uint64_t retval;
    uint64_t code;
    uint64_t args;
    int socket, core;
    int sec_counter;
    int generator_status;

    socket = rte_socket_id();
    core = rte_lcore_id();
    pkt_counter = 0;
    sec_counter = 0;
    remaining_packets_to_send = 0;
    num_of_free_mbufs = 0;
    generator_status = 0;

    get_void_arg_bytes(&worker_settings,
                       arg,
                       sizeof(worker_settings),
                       true);

    rate_limiter_init(&rate_limiter,
                      worker_settings.rate_limit,
                      worker_settings.batch_size,
                      worker_settings.tx_queue_num);

    thread_sync_register(&ts_signal);

    /* Packet limit is divided by the number of TX queues */
    worker_settings.packet_limit =
        worker_settings.queue_index ? 
        floor((double)worker_settings.packet_limit / tx_settings.tx_queues) :
        ceil((double)worker_settings.packet_limit / tx_settings.tx_queues);

    /* Allocate mempool */
    rte_mempool = create_mempool(socket,
                                 DEVICE_MEMPOOL_DEF_SIZE,
                                 tx_settings.tx_descs*2);

    map_init(&srcip_stats_local, MAP_INITIAL_SIZE);

    while(tx_running.val) {

        /* Parse signals */
        thread_sync_read_relaxed(&ts_signal, &code, &args);
        if (code == SIGNAL_STOP) {
            break;
        } else if (code == SIGNAL_PAUSE) {
            usleep(100);
            continue;
        } else if (code != SIGNAL_RUNNING) {
            /* Sync with all threads */
            retval = thread_sync_full_barrier(&ts_signal);
            /* Act according to code */
            if (code & SIGNAL_RESTART) {
                pkt_counter = 0;
                remaining_packets_to_send = 0;
                sec_counter = 0;
                generator_status = 0;
                /* The leader resets the packet generator */
                if (retval == THREAD_SYNC_WAIT_LEADER) {
                    reset_packet_generator(&worker_settings);
                }
            }
            if (code & SIGNAL_RATELIMITER) {
                rate_limiter_init(&rate_limiter,
                                  args,
                                  worker_settings.batch_size,
                                  worker_settings.tx_queue_num);
                adaptive_speed_set(0);
            }
            if (code & SIGNAL_MULTIPLIER) {
                rate_limiter_init(&rate_limiter,
                                  0,
                                  worker_settings.batch_size,
                                  worker_settings.tx_queue_num);
                adaptive_speed_set(args);
            }
            /* Release all other threads */
            if (retval == THREAD_SYNC_WAIT_LEADER) {
                thread_sync_set_event(&ts_signal, SIGNAL_RUNNING, 0);
                thread_sync_continue(&ts_signal);
            }
        }

        /* Allocate mbufs */
        retval = tx_allocate_mbufs(rte_mempool,
                                   rte_mbufs,
                                   &worker_settings,
                                   &num_of_free_mbufs,
                                   &pkt_counter);
        if (retval) {
            printf("** RTE Error: failed to allocate mbuf "
                   "on TX queue %d **\n",
                   worker_settings.queue_index);
        }

        /* Fill packets in batch */
        generator_status = tx_generate_batch(rte_mbufs,
                                             &worker_settings,
                                             &remaining_packets_to_send,
                                             &pkt_counter);

        retval = tx_send_batch(rte_mbufs,
                               &worker_settings,
                               &srcip_stats_local,
                               remaining_packets_to_send);
        
        remaining_packets_to_send -= retval;
        num_of_free_mbufs -= retval;

        tx_show_counter(socket,
                        core,
                        &worker_settings,
                        &sec_counter);

        rate_limiter_wait(&rate_limiter);

        /* Time and other events limit */
        if (tx_event_limit(&worker_settings,
                           core,
                           generator_status,
                           &sec_counter,
                           &pkt_counter)) {
            break;
        }
    }

    /* Push values from local map into global map */
    stats_fill_srcip_map(&worker_settings, &srcip_stats_local, true);
    map_destroy(&srcip_stats_local);
    thread_sync_unregister(&ts_signal);

    printf("TX worker %d exit \n", worker_settings.queue_index);
    
    return 0;
}

/* Main RX worker */
static int
lcore_rx_worker(void *arg)
{
    struct rte_mbuf *rte_mbufs[MAX_BATCH_SIZE];
    struct worker_settings worker_settings;
    struct map ftuple_stats_local;
    struct map srcip_stats_local;
    struct vector *latency_stats_local;
    uint64_t code;
    int packets;
    int core;
    int gap;

    get_void_arg_bytes(&worker_settings,
                       arg,
                       sizeof(worker_settings),
                       true);
    core = rte_lcore_id();

    /* Initiate containers for collecting statistics */
    latency_stats_local = vector_init(sizeof(uint64_t));
    map_init(&ftuple_stats_local, MAP_INITIAL_SIZE);
    map_init(&srcip_stats_local, MAP_INITIAL_SIZE);

    gap = MIN(worker_settings.stats_gap, worker_settings.batch_size);

    while(1) {

        /* Parse signals */
         thread_sync_read_relaxed(&ts_signal, &code, NULL);
         if (code == SIGNAL_STOP) {
             break;
         } else if (code == SIGNAL_PAUSE) {
             usleep(100);
             continue;
         }

        /* Get a batch of packets */
        packets = rx_receive_batch(&worker_settings,
                                   rte_mbufs);

        /* Parse packets, update latency vector */
        rx_parse_packets(&worker_settings,
                        rte_mbufs,
                        packets,
                        gap,
                        latency_stats_local,
                        &ftuple_stats_local,
                        &srcip_stats_local);

        /* Free allocated memory */
        rx_free_memory(rte_mbufs, packets);

        /* Update pingpong lock if enabled */
        if (packets && worker_settings.pingpong) {
            atomic_store(&pingpong_send.val, 1);
        }

        /* Leader prints to screen */
        rx_show_counter(core, &worker_settings);
    }

    /* Push values from local vector into the global vector */
    stats_fill_latency_vector(&worker_settings, latency_stats_local);
    vector_destroy(latency_stats_local);

    /* Push values from local map into the global map */
    stats_fill_ftuple_map(&worker_settings, &ftuple_stats_local);
    map_destroy(&ftuple_stats_local);

    /* Push values from local map into global map */
    stats_fill_srcip_map(&worker_settings, &srcip_stats_local, false);
    map_destroy(&srcip_stats_local);

    printf("RX worker %d exit \n", worker_settings.queue_index);
    return 0;
}

// pulls from perf buffer and produces either pcap or text output;
// we don't bother with ANY cleanup as the program exits after running consumer

#define _GNU_SOURCE // pipe2 and similar extensions

#include "xdptrace.h"
#include "xpcapng.h"
#include "hashmap.h"
#include "fasthash.h"
#include "trace_meta.h"

#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if.h>
#include <linux/perf_event.h>
#include <pcap/dlt.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/signal.h>

struct consumer {
    struct perf_buffer *perf;
    int epoll_fd;

    const struct xdp_prog *prog;
    FILE *text_output;
    struct xpcapng_dumper *pcap;
    struct hashmap ifmap; // ifkey -> long

    __u64 packet_id;

    int ifindex;
    char if_name[IFNAMSIZ];

    __u64 nsamples;
    __u64 nsamples_lost;

    int name_col_width;
    bool t_flag;
};

struct ifkey {
    char  if_name[IFNAMSIZ];
    __u64 labeli;
    __u64 link_type;
};

static size_t
ifkey_hash_fn(long key, void *ctx) {
    (void)ctx;
    const struct ifkey *ifkey = (typeof(ifkey))key;

    struct fh64 fh64 = fh64_init(0, 32);
    for (int i = 0; i < 4; ++i) {
        static_assert(sizeof(*ifkey) == sizeof(__u64) * 4, "");
        fh64 = fh64_update(fh64, ((const __u64 *)ifkey)[i]);
    }
    return fh64_final(fh64);
}

static bool
ifkey_equal_fn(long k1, long k2, void *ctx) {
    (void)ctx;
    return memcmp((const struct ifkey *)k1, (const struct ifkey *)k2,
                  sizeof(struct ifkey)) == 0;
}

static enum bpf_perf_event_ret
consumer_handle_pkt(void *private_data, int cpu, struct perf_event_header *event);

static struct rc
consumer_init(struct consumer *consumer, const struct consumer_params *params) {

    memset(consumer, 0, sizeof(*consumer));
    consumer->ifmap = (struct hashmap)HASHMAP_INIT(ifkey_hash_fn, ifkey_equal_fn, 0);
    consumer->packet_id = 1;
    consumer->prog = params->progs->progs;

    struct perf_event_attr perf_attr = {
        .sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TIME,
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_BPF_OUTPUT,
        .sample_period = 1,
        .wakeup_events = 1,
        .clockid = CLOCK_REALTIME,
        .use_clockid = 1,
        .size = sizeof(perf_attr),
    };

    struct perf_buffer_raw_opts perf_opts = {
        .attr = &perf_attr,
        .event_cb = &consumer_handle_pkt,
        .ctx = consumer,
    };

    if (!(consumer->perf = perf_buffer__new_raw(params->map_fd, 256, &perf_opts))) {
        LOG_ERRNO("Failed to init perf buffer");
        return FAILURE;
    }

    struct epoll_event perf_buffer_ready = { .events = EPOLLIN  };
    struct epoll_event term = { .events = EPOLLIN, .data = { .u32 = 1 } };

    if ((consumer->epoll_fd = epoll_create1(EPOLL_CLOEXEC)) == -1) {
        LOG_INTERNAL_ERROR();
        return FAILURE;
    }

    if (epoll_ctl(consumer->epoll_fd, EPOLL_CTL_ADD,
                  perf_buffer__epoll_fd(consumer->perf), &perf_buffer_ready
                 ) != 0) {
        LOG_INTERNAL_ERROR();
        return FAILURE;
    }

    if (epoll_ctl(consumer->epoll_fd, EPOLL_CTL_ADD, params->term_eventfd, &term) != 0) {
        LOG_INTERNAL_ERROR();
        return FAILURE;
    }

    for (size_t i = 0; i != params->progs->nprogs; ++i) {
        int len = (int)strlen(xdp_prog(params->progs, i)->name.name);
        if (len > consumer->name_col_width)
            consumer->name_col_width = len;
    }

    consumer->t_flag = params->t_flag;
    return SUCCESS;
}

static struct rc
consumer_run(struct consumer *consumer) {
    for (;;) {
        struct epoll_event event[2];
        int rc = epoll_wait(consumer->epoll_fd, event, 2, -1);
        if (rc == -1) {
            if (errno == EINTR) continue;
            LOG_ERRNO("epoll_wait");
            return FAILURE;
        }

        if (perf_buffer__consume(consumer->perf) != 0) {
            LOG_ERRNO("perf_buffer__consume");
            return FAILURE;
        }

        // Did term event fire?
        if (event[0].data.u32 == 1 || rc == 2 && event[1].data.u32 == 1)
            break;
    }
    return SUCCESS;
}

static void
consumer_report_sample_counts(struct consumer *consumer) {
    fprintf(stderr, "\n%20llu captured\n%20llu lost\n",
            consumer->nsamples, consumer->nsamples_lost);
}

struct rc
consumer_run_emit_pcapng(const struct consumer_params *params, const char *output_path) {
    struct consumer consumer;
    if (failed(consumer_init(&consumer, params))) return FAILURE;

    FILE *output = stdout;

    if (strcmp(output_path, "-")) {
        if (!(output = fopen(output_path, "w"))) {
            LOG_ERRNO("Failed to open '%s'", output_path);
            return FAILURE;
        }
    }

    if (!(consumer.pcap = xpcapng_dump_open(output, 0, 0, 0, 0))) {
        LOG_ERRNO("Failed to write pcapng header");
        return FAILURE;
    }

    struct rc rc = consumer_run(&consumer);

    if (output != stdout && fclose(output) != 0) {
        LOG_ERRNO("Failed to flush output");
        rc = FAILURE;
    }

    consumer_report_sample_counts(&consumer);
    return rc;
}

static struct rc
tcpdump_pipe(int pipefd[2], const char *flags) {

    int in_pipefd[2], out_pipefd[2];
    if (pipe2(in_pipefd, O_CLOEXEC) != 0 || pipe2(out_pipefd, O_CLOEXEC) != 0) {
        LOG_INTERNAL_ERROR();
        return FAILURE;
    }

    pid_t pid;
    switch ((pid = fork())) {
    case 0:
        if (dup2(in_pipefd[0], STDIN_FILENO) != -1
            && dup2(out_pipefd[1], STDOUT_FILENO) != -1
            && prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == 0
            && setsid() != -1 // detach from controlling terminal,
                              // so that ^C does not interrupt tcpdump
        ) {
            static char tcpdump[] = "/usr/bin/tcpdump";
            char *prog = getenv("TCPDUMP");
            if (!prog) prog = tcpdump;
            char *argv[] = { prog, "-r", "-", (char *)flags, NULL };
            // extra pipe ends are closed due to O_CLOEXEC
            execve(prog, argv, environ);
            LOG_ERRNO("Error running %s", prog);
            return FAILURE;
        }
        // fallthrough
    case -1:
        LOG_INTERNAL_ERROR();
        return FAILURE;
    }

    pipefd[0] = out_pipefd[0]; // r
    pipefd[1] = in_pipefd[1]; // w
    close(in_pipefd[0]);
    close(out_pipefd[1]);
    return SUCCESS;
}

struct merger_params {
    FILE *tcpdump_out;
    FILE *text_out;
};

static void *
merger_threadfunc(void *p);

struct rc
consumer_run_emit_text(const struct consumer_params *params) {

    char tcpdump_flags[128] = "-tnl";
    if (params->e_flag) strcat(tcpdump_flags, "e");

    struct consumer consumer;
    if (failed(consumer_init(&consumer, params))) return FAILURE;

    // tcpdump pipe
    int tcpdump_pipefd[2];
    if (failed(tcpdump_pipe(tcpdump_pipefd, tcpdump_flags))) return FAILURE;
    FILE *tcpdump_in = fdopen(tcpdump_pipefd[1], "w");
    FILE *tcpdump_out = fdopen(tcpdump_pipefd[0], "r");
    if (!tcpdump_in || !tcpdump_out) {
        LOG_INTERNAL_ERROR();
        return FAILURE;
    }

    // text pipe
    int textpipe_pipefd[2];
    FILE *textpipe_in, *textpipe_out;
    if (pipe2(textpipe_pipefd, O_CLOEXEC) == -1
        || !(textpipe_in = fdopen(textpipe_pipefd[1], "w"))
        || !(textpipe_out = fdopen(textpipe_pipefd[0], "r"))
        ) {
        LOG_INTERNAL_ERROR();
        return FAILURE;
    }
    setvbuf(textpipe_in, NULL, _IOLBF, 0);

    consumer.text_output = textpipe_in;
    if (!(consumer.pcap = xpcapng_dump_open(tcpdump_in, 0, 0, 0, 0))) {
        LOG_ERRNO("Failed to write pcapng header");
        return FAILURE;
    }

    struct merger_params merger_params = {
        .tcpdump_out = tcpdump_out,
        .text_out = textpipe_out,
    };

    pthread_t merger_thread;
    int err = pthread_create(&merger_thread, NULL, merger_threadfunc, &merger_params);
    if (err) {
        LOG_INTERNAL_ERROR();
        return FAILURE;
    }

    struct rc rc = consumer_run(&consumer);

    fclose(tcpdump_in);
    fclose(textpipe_in);

    pthread_join(merger_thread, NULL);

    consumer_report_sample_counts(&consumer);

    return rc;
}

static const char *
xdp_verdict_to_str(int verdict, char *buf, size_t sz) {
    static const char map[][16] = {
        [XDP_ABORTED] = "ABORTED",
        [XDP_DROP] = "DROP",
        [XDP_PASS] = "PASS",
        [XDP_TX] = "TX",
        [XDP_REDIRECT] = "REDIRECT",
    };
    if (verdict < sizeof(map) / sizeof(map[0]) && *map[verdict])
        return map[verdict];
    snprintf(buf, sz, "%d", verdict);
    return buf;
}

static enum bpf_perf_event_ret
consumer_handle_pkt(void *private_data, int cpu, struct perf_event_header *event) {
    struct consumer *consumer = private_data;

    switch (event->type) {

    case PERF_RECORD_LOST:

        struct {
            struct perf_event_header h;
            __u64 id;
            __u64 lost;
        } *lost = (void *)event;

        consumer->nsamples_lost += lost->lost;
        break;

    case PERF_RECORD_SAMPLE:

        struct {
            struct perf_event_header h;
            __u64 time;
            __u32 size;
            struct trace_meta meta;
            __u8 pkt[];

        } *sample = (void *)event;

        const int hook_index = sample->meta.hook_index;
        const struct xdp_prog *prog = &consumer->prog[hook_index / 2];
        const struct xdp_meta *meta = &prog->meta.entry;

        // A trace is comprised of 1+ <entry> samples and a single <exit>
        // sample.  Kernel-user channel is lossy though, therefore we
        // might observe <entry> on if_1 followed by <entry> on if_2.
        // Start a new trace if the interface is not as expected.
        // Note: comparing both index and name as neither is unique when
        // multiple namespaces are involved.
        //
        // New trace starting?
        if (consumer->ifindex != sample->meta.ifindex
            || strcmp(consumer->if_name, sample->meta.if_name)
        ) {
            consumer->ifindex = sample->meta.ifindex;
            strcpy(consumer->if_name, sample->meta.if_name);
            ++consumer->packet_id;

            if (consumer->text_output)
                fprintf(consumer->text_output, "%s:\n", sample->meta.if_name);
        }

        const char *label;
        __u64 labeli; // uniquely identifies the label
        char verdict[8];

        if (hook_index & 1) {
            // <Exit> sample.
            // Reset interface so that the subsequent packet will
            // satisfy the check above, starting a new trace
            consumer->ifindex = 0;
            consumer->if_name[0] = 0;

            if (sample->meta.res == XDP_PASS
                || sample->meta.res == XDP_TX
                || sample->meta.res == XDP_REDIRECT
            ) {
                meta = &prog->meta.exit;
            }

            label = xdp_verdict_to_str(sample->meta.res, verdict, sizeof(verdict));
            labeli = ~(__u64)sample->meta.res;
        } else {
            // <Entry> sample.
            label = prog->name.name;
            labeli = hook_index;
        }

        if (consumer->text_output) {
            char ts[32];
            if (consumer->t_flag) {
                ts[0] = 0;
            } else {
                __u64 sec = sample->time / (__u64)1e9;
                __u64 nsec = sample->time % (__u64)1e9;
                sprintf(ts, "%02d:%02d:%02d:%06d  ",
                        (int)((sec / 60 / 60) % 24),
                        (int)((sec / 60) % 60),
                        (int)(sec % 60),
                        (int)(nsec / 1000));
            }
            fprintf(consumer->text_output, "  %s%-*s  \e\n", ts, consumer->name_col_width, label);
        }

        // Lookup or create PCAP interface record
        long pcap_ifindex;
        struct ifkey transient_ifkey = { .labeli = labeli, .link_type = meta->link_type };
        memcpy(transient_ifkey.if_name, sample->meta.if_name, sizeof(sample->meta.if_name));
        if (!hashmap__find(&consumer->ifmap, &transient_ifkey, &pcap_ifindex)) {
            char pcap_if_name[256];
            snprintf(
                pcap_if_name, sizeof(pcap_if_name), "%s:%s",
                sample->meta.if_name, label
            );
            const int nsec_ts_resol = 9;
            pcap_ifindex = xpcapng_dump_add_interface(
                consumer->pcap, 262144, pcap_if_name, 0, 0, 0, nsec_ts_resol, 0,
                // tcpdump doesn't support multiple interfaces with
                // different link types; wrap in PPI if piping through tcpdump
                consumer->text_output ? DLT_PPI : meta->link_type
            );
            if (pcap_ifindex < 0) {
                LOG_ERRNO("Failed to append record to pcap file");
                return LIBBPF_PERF_EVENT_ERROR;
            }
            struct ifkey *ifkey = malloc(sizeof(*ifkey));
            if (!ifkey) {
                LOG_INTERNAL_ERROR();
                return LIBBPF_PERF_EVENT_ERROR;
            }
            memcpy(ifkey, &transient_ifkey, sizeof(*ifkey));
            if (hashmap__set(&consumer->ifmap, ifkey, pcap_ifindex, NULL, NULL) != 0) {
                LOG_INTERNAL_ERROR();
                return LIBBPF_PERF_EVENT_ERROR;
            }
        }

        void *pkt = &sample->pkt[0] + meta->pseudo_sz;
        __u32 pkt_len = sample->meta.pkt_len - meta->pseudo_sz;
        __u32 cap_len = sample->meta.cap_len - meta->pseudo_sz;

        struct xpcapng_epb_options_s opts = {
            .packetid = (void *)&consumer->packet_id,
            .ppi_linktype = consumer->text_output ? meta->link_type : 0,
        };

        if (meta->pseudo_type_id > 0) {
            opts.comment = "TODO: pseudohdr content appears here";
        }

        if (!xpcapng_dump_enhanced_pkt(
                consumer->pcap, pcap_ifindex, pkt, pkt_len, cap_len, sample->time, &opts
            )) {
            LOG_ERRNO("Failed to save packet to pcap file");
            return LIBBPF_PERF_EVENT_ERROR;
        }

        consumer->nsamples += 1;
        break;
    }

    return LIBBPF_PERF_EVENT_CONT;
}

// Merges 2 text streams:
//  - output from consumer_handle_pkt with \e placeholders for packet bodies
//  - tcpdump output
static void *
merger_threadfunc(void *p) {
    struct merger_params *params = p;
    char buf1[512], buf2[512];

    for (;;) {
        if (!fgets(buf1, sizeof(buf1), params->text_out)) break;

        char *p = strchr(buf1, '\e');
        if (!p) {
            fputs(buf1, stdout);
            continue;
        }
        *p = 0;
        fputs(buf1, stdout);
        memset(buf1, ' ', p - buf1);

        for (;;) {
readmore:
            if (!fgets(buf2, sizeof(buf2), params->tcpdump_out)) break;
            fputs(buf2, stdout);
            if (!strchr(buf2, '\n')) goto readmore;

            // tcpdump could produce multiple lines of output for some
            // packets; continuation lines start with \t
            int c = fgetc(params->tcpdump_out);
            if (c == EOF) break;

            ungetc(c, params->tcpdump_out);
            if (c != '\t') break;

            fputs(buf1, stdout);
        }
    }

    return 0;
}

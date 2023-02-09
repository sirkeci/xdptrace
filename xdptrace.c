#include <assert.h>
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>

#include "xdptrace.h"
#include "trace_kern.skel.h"
#include "trace_meta.h"


bool verbose;
bool keep_going = true;

struct xdp_prog {
    struct bpf_prog_name  name;
    int                   prog_fd;
    struct btf           *btf;

    struct xdp_prog_meta  meta;

    struct trace_kern    *tk;
};

static int
xdp_prog_init_with_id(int id, struct xdp_prog *buf, struct xdp_prog **prog) {

    int rc;

    *prog = 0;
    memset(buf, 0,  sizeof(*prog));

    if ((buf->prog_fd = bpf_prog_get_fd_by_id(id)) < 0) {
        if (errno == ENOENT) return 0;
        fprintf(stderr, "Failed to open BPF program %d: %s\n", id, strerror(errno));
        return -1;
    }

    struct bpf_prog_info info = {};
    __u32 len = sizeof(info);

    if (bpf_obj_get_info_by_fd(buf->prog_fd, &info, &len) != 0) {
        fprintf(stderr, "Failed to obtain info on BPF program %d: %s\n",
                id, strerror(errno));
        rc = -1;
        goto out_close;
    }

    if (info.type != BPF_PROG_TYPE_XDP) {
        rc = 0;
        goto out_close;
    }

    if (!info.btf_id) {
        fprintf(stderr, "Program %s (%d) lacks BTF\n", info.name, id);
        rc = keep_going ? 0 : -1;
        goto out_close;
    }

    if (!(buf->btf = btf__load_from_kernel_by_id(info.btf_id))) {
        fprintf(stderr, "Failed to load BTF for %s (%d): %s\n",
                        info.name, id, strerror(errno));
        rc = -1;
        goto out_close;
    }

    struct bpf_prog_short_name sname;
    static_assert(sizeof(sname.name) == sizeof(info.name), "");
    strcpy(sname.name, info.name);
    sname.id = id;

    if (bpf_prog_full_name(buf->btf, sname, &buf->name) != 0
        || parse_xdp_prog_meta(buf->btf, buf->name, &buf->meta) != 0
    ) {
        rc = -1;
        goto out_free_btf;
    }

    if (verbose) fprintf(stderr, "Init %s (%d): link_type: %d, pseudo_sz: %d\n",
                         buf->name.name, buf->name.id,
                         buf->meta.entry.link_type,
                         buf->meta.entry.pseudo_sz);
    *prog = buf;
    return 0;

out_free_btf:
    btf__free(buf->btf);
out_close:
    close(buf->prog_fd);
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

struct handle_pkt_ctx {
    const struct xdp_prog *prog;
    __u64 packet_id;
};

static enum bpf_perf_event_ret
handle_pkt(void *private_data,
           int cpu, struct perf_event_header *event) {

    struct handle_pkt_ctx *ctx = private_data;

    if (event->type == PERF_RECORD_SAMPLE) {
        struct {
            struct perf_event_header *h;
            __u64 time;
            __u32 size;
            struct trace_meta meta;
            __u8 pkt[];

        } *sample = (void *)event;
        const int hook_index = sample->meta.hook_index;
        const struct xdp_prog *prog = &ctx->prog[hook_index / 2];
        if (hook_index & 1) {
            char verdict[8];
            printf("%s: %s -> %s\t\n",
                   sample->meta.if_name, prog->name.name,
                   xdp_verdict_to_str(sample->meta.res, verdict, sizeof(verdict))
            );
            ++ctx->packet_id;
        } else {
            printf("%s: -> %s\t\n", sample->meta.if_name, prog->name.name);
        }

        // TODO: pipe packet through tcpdump, sample.pkt, lengths in sample->meta
        // prog->meta.{entry,exit} conveys linktype and pseudo_sz (also
        // pseudo_type_id to decode and pretty-print pseudo header
        // according to prog->btf).
    }

    return LIBBPF_PERF_EVENT_CONT;
}

int main(int argc, char **argv) {

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    verbose = !!getenv("VERBOSE");

    enum { N = 128 }; // TODO
    struct xdp_prog prog[N];
    int n = 0;

    // Open the first N XDP programs and extract metadata
    for (__u32 id = 0; n != N; ) {

        if (bpf_prog_get_next_id(id, &id) != 0) {
            if (errno == ENOENT) break;
            fprintf(stderr, "Error listing BPF programs: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        struct xdp_prog *p;

        if (xdp_prog_init_with_id(id, &prog[n], &p) != 0)
            return EXIT_FAILURE;

        // Was it an XDP program?  We can encounter different prog kinds.
        if (p) ++n;
    }

    if (n == 0) {
        fprintf(stderr, "No XDP programs found\n");
        return EXIT_FAILURE;
    }

    // Attach hooks
    for (int i = 0; i != n; ++i) {

        if (!(prog[i].tk = trace_kern__open())) {
            fprintf(stderr, "Failed to open tracing program: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        // Crucial for load success (type checking).
        if (bpf_program__set_attach_target(
                prog[i].tk->progs.xdp_entry_hook,
                prog[i].prog_fd,
                "xdp_trace_entry__") != 0
            || bpf_program__set_attach_target(
                prog[i].tk->progs.xdp_exit_hook,
                prog[i].prog_fd,
                "xdp_trace_exit__") != 0
        ) {
            fprintf(stderr, "Failed to prepare tracing program for %s (%d): %s\n",
                    prog[i].name.name, prog[i].name.id, strerror(errno));
            if (keep_going) continue;
            return EXIT_FAILURE;
        }

        prog[i].tk->rodata->hook_index = i * 2;
        prog[i].tk->rodata->snap_len = 256;

        if (i != 0) { // Fold maps
            if ( bpf_map__reuse_fd(
                    prog[i].tk->maps.trace_perf_map,
                    bpf_map__fd(prog[0].tk->maps.trace_perf_map)) != 0
            ) {
                fprintf(stderr, "Failed to configure maps for the tracing program: %s\n",
                        strerror(errno));
                return EXIT_FAILURE;
            }
        }

        // Load
        if (trace_kern__load(prog[i].tk) != 0) {
            fprintf(stderr, "Failed to load tracing program for %s (%d): %s\n",
                    prog[i].name.name, prog[i].name.id, strerror(errno));
            if (keep_going) continue;
            return EXIT_FAILURE;
        }

        // Attach hooks
        prog[i].tk->links.xdp_entry_hook =
            bpf_program__attach(prog[i].tk->progs.xdp_entry_hook);
        prog[i].tk->links.xdp_exit_hook =
            bpf_program__attach(prog[i].tk->progs.xdp_exit_hook);

        if (!prog[i].tk->links.xdp_entry_hook || !prog[i].tk->links.xdp_exit_hook) {
            fprintf(stderr, "Failed to hook %s (%d): %s\n",
                    prog[i].name.name, prog[i].name.id, strerror(errno));
            return EXIT_FAILURE;
        }
    }

    if (verbose)
        fprintf(stderr, "Ready to go\n");

    // Process events
    struct perf_event_attr perf_attr = {
        .sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TIME,
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_BPF_OUTPUT,
        .sample_period = 1,
        .wakeup_events = 1,
    };
    struct handle_pkt_ctx ctx = { .prog = prog, .packet_id = 1 };
    struct perf_buffer_raw_opts perf_opts = {
        .attr = &perf_attr,
        .event_cb = handle_pkt,
        .ctx = &ctx,
    };

    struct perf_buffer *perf = perf_buffer__new_raw(
        bpf_map__fd(prog[0].tk->maps.trace_perf_map),
        256, &perf_opts
    );

    for (;;) {
        perf_buffer__poll(perf, 1000);
    }

    return 0;
}

#include <assert.h>
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <getopt.h>
#include <signal.h>
#include <sys/eventfd.h>

#include "xdptrace.h"
#include "trace_kern.skel.h"
#include "trace_meta.h"


bool verbose;
bool keep_going = true;

static int
xdp_prog_init_with_id(int id, struct xdp_prog *buf, struct xdp_prog **prog) {

    int rc;

    *prog = 0;
    memset(buf, 0,  sizeof(*prog));

    if ((buf->prog_fd = bpf_prog_get_fd_by_id(id)) < 0) {
        if (errno == ENOENT) return 0;
        LOG_ERRNO("Failed to open BPF program %d", id);
        return -1;
    }

    struct bpf_prog_info info = {};
    __u32 len = sizeof(info);

    if (bpf_obj_get_info_by_fd(buf->prog_fd, &info, &len) != 0) {
        LOG_ERRNO("Failed to obtain info on BPF program %d", id);
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
        LOG_ERRNO("Failed to load BTF for %s (%d)", info.name, id);
        rc = -1;
        goto out_close;
    }

    struct bpf_prog_short_name sname;
    static_assert(sizeof(sname.name) == sizeof(info.name), "");
    strcpy(sname.name, info.name);
    sname.id = id;

    if (failed(bpf_prog_full_name(buf->btf, sname, &buf->name))
        || failed(parse_xdp_prog_meta(buf->btf, buf->name, &buf->meta))
    ) {
        rc = keep_going ? 0 : -1;
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

static int term_eventfd;

void sig_handler(int sig) {
    (void)sig;
    __u64 v = 1;
    write(term_eventfd, &v, sizeof(v));
}

int main(int argc, char **argv) {

    struct sigaction sa = {
        .sa_handler = sig_handler,
        // the handler is reset to default action (term) once it fires;
        // the second ^C terminates the app if we get stuck in the clean
        // shutdown after the first ^C
        .sa_flags = SA_RESETHAND | SA_RESTART
    };
    if ((term_eventfd = eventfd(0, EFD_CLOEXEC)) == -1
        || sigaction(SIGINT, &sa, NULL) != 0
        || sigaction(SIGTERM, &sa, NULL) != 0
       ) {
        LOG_INTERNAL_ERROR();
        return EXIT_FAILURE;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    verbose = !!getenv("VERBOSE");

    const char *output_filename = NULL;
    struct consumer_params consumer_params = {};

    // Parse command line
    int opt;
    while ((opt = getopt(argc, argv, "w:e")) != -1) {

        switch (opt) {
        case 'w':
            output_filename = optarg; break;
        case 'e':
            consumer_params.e_flag = true; break;
        }
    }

    enum { N = 128 }; // TODO
    struct xdp_prog prog[N];
    int n = 0;

    // Open the first N XDP programs and extract metadata
    for (__u32 id = 0; n != N; ) {

        if (bpf_prog_get_next_id(id, &id) != 0) {
            if (errno == ENOENT) break;
            LOG_ERRNO("Error listing BPF programs");
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
            LOG_ERRNO("Failed to open tracing program");
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
            LOG_ERRNO("Failed to prepare tracing program for %s (%d)",
                       prog[i].name.name, prog[i].name.id);
            if (keep_going) continue;
            return EXIT_FAILURE;
        }

        prog[i].tk->rodata->hook_index = i * 2;
        prog[i].tk->rodata->snap_len = 512;

        if (i != 0) { // Fold maps
            if ( bpf_map__reuse_fd(
                    prog[i].tk->maps.trace_perf_map,
                    bpf_map__fd(prog[0].tk->maps.trace_perf_map)) != 0
            ) {
                LOG_ERRNO("Failed to configure maps for the tracing program");
                return EXIT_FAILURE;
            }
        }

        // Load
        if (trace_kern__load(prog[i].tk) != 0) {
            LOG_ERRNO("Failed to load tracing program for %s (%d)",
                      prog[i].name.name, prog[i].name.id);
            if (keep_going) continue;
            return EXIT_FAILURE;
        }

        // Attach hooks
        prog[i].tk->links.xdp_entry_hook =
            bpf_program__attach(prog[i].tk->progs.xdp_entry_hook);
        prog[i].tk->links.xdp_exit_hook =
            bpf_program__attach(prog[i].tk->progs.xdp_exit_hook);

        if (!prog[i].tk->links.xdp_entry_hook || !prog[i].tk->links.xdp_exit_hook) {
            LOG_ERRNO("Failed to hook %s (%d)", prog[i].name.name, prog[i].name.id);
            return EXIT_FAILURE;
        }
    }

    if (verbose)
        fprintf(stderr, "Ready to go\n");

    consumer_params.map_fd = bpf_map__fd(prog[0].tk->maps.trace_perf_map);
    consumer_params.term_eventfd = term_eventfd;
    consumer_params.progs = prog;

    if (output_filename) {
        if (failed(consumer_run_emit_pcapng(&consumer_params, output_filename)))
            return EXIT_FAILURE;
    } else {
        if (failed(consumer_run_emit_text(&consumer_params)))
            return EXIT_FAILURE;
    }

    return 0;
}

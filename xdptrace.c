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

// returns pointer to an element to fill in, doesn't bump nprogs
static struct xdp_prog *xdp_progs_begin_push(struct xdp_progs *progs) {
    if (progs->nprogs == progs->capacity) {
        size_t capacity = progs->capacity ? 2 * progs->capacity : 32;
        struct xdp_prog *buf = realloc(progs->progs, capacity * sizeof(*buf));
        if (!buf) return NULL;
        progs->progs = buf;
        progs->capacity = capacity;
    }
    return &progs->progs[progs->nprogs];
}

static struct rc
xdp_prog_init_with_id(int id, struct xdp_progs *progs) {

    struct rc rc;

    struct xdp_prog *buf = xdp_progs_begin_push(progs);
    if (!buf) {
        LOG_INTERNAL_ERROR();
        return FAILURE;
    }
    memset(buf, 0,  sizeof(*buf));

    if ((buf->prog_fd = bpf_prog_get_fd_by_id(id)) < 0) {
        if (errno == ENOENT) return SUCCESS;
        LOG_ERRNO("Failed to open BPF program %d", id);
        return FAILURE;
    }

    struct bpf_prog_info info = {};
    __u32 len = sizeof(info);

    if (bpf_obj_get_info_by_fd(buf->prog_fd, &info, &len) != 0) {
        LOG_ERRNO("Failed to obtain info on BPF program %d", id);
        rc = FAILURE;
        goto out_close;
    }

    if (info.type != BPF_PROG_TYPE_XDP) {
        rc = SUCCESS;
        goto out_close;
    }

    if (!info.btf_id) {
        fprintf(stderr, "Program %s (%d) lacks BTF\n", info.name, id);
        rc = keep_going ? SUCCESS : FAILURE;
        goto out_close;
    }

    if (!(buf->btf = btf__load_from_kernel_by_id(info.btf_id))) {
        LOG_ERRNO("Failed to load BTF for %s (%d)", info.name, id);
        rc = FAILURE;
        goto out_close;
    }

    struct bpf_prog_short_name sname;
    static_assert(sizeof(sname.name) == sizeof(info.name), "");
    strcpy(sname.name, info.name);
    sname.id = id;

    if (failed(bpf_prog_full_name(buf->btf, sname, &buf->name))
        || failed(parse_xdp_prog_meta(buf->btf, buf->name, &buf->meta))
    ) {
        rc = keep_going ? SUCCESS : FAILURE;
        goto out_free_btf;
    }

    if (verbose) fprintf(stderr, "Init %s (%d): link_type: %d, pseudo_sz: %d\n",
                         buf->name.name, buf->name.id,
                         buf->meta.entry.link_type,
                         buf->meta.entry.pseudo_sz);
    ++progs->nprogs;
    return SUCCESS;

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

    struct xdp_progs progs = {};

    // Open ALL XDP programs and extract metadata
    for (__u32 id = 0;;) {

        if (bpf_prog_get_next_id(id, &id) != 0) {
            if (errno == ENOENT) break;
            LOG_ERRNO("Error listing BPF programs");
            return EXIT_FAILURE;
        }

        if (failed(xdp_prog_init_with_id(id, &progs)))
            return EXIT_FAILURE;
    }

    if (progs.nprogs == 0) {
        fprintf(stderr, "No XDP programs found\n");
        return EXIT_FAILURE;
    }

    // Attach hooks
    for (size_t i = 0; i != progs.nprogs; ++i) {

        struct xdp_prog *prog = xdp_prog(&progs, i);

        if (!(prog->tk = trace_kern__open())) {
            LOG_ERRNO("Failed to open tracing program");
            return EXIT_FAILURE;
        }

        // Crucial for load success (type checking).
        if (bpf_program__set_attach_target(
                prog->tk->progs.xdp_entry_hook,
                prog->prog_fd,
                "xdp_trace_entry__") != 0
            || bpf_program__set_attach_target(
                prog->tk->progs.xdp_exit_hook,
                prog->prog_fd,
                "xdp_trace_exit__") != 0
        ) {
            LOG_ERRNO("Failed to prepare tracing program for %s (%d)",
                       prog->name.name, prog->name.id);
            if (keep_going) continue;
            return EXIT_FAILURE;
        }

        prog->tk->rodata->hook_index = i * 2;
        prog->tk->rodata->snap_len = 512;

        if (i != 0) { // Fold maps
            if (bpf_map__reuse_fd(
                    prog->tk->maps.trace_perf_map,
                    bpf_map__fd(xdp_prog(&progs, 0)->tk->maps.trace_perf_map)) != 0
            ) {
                LOG_ERRNO("Failed to configure maps for the tracing program");
                return EXIT_FAILURE;
            }
        }

        // Load
        if (trace_kern__load(prog->tk) != 0) {
            LOG_ERRNO("Failed to load tracing program for %s (%d)",
                      prog->name.name, prog->name.id);
            if (keep_going) continue;
            return EXIT_FAILURE;
        }

        // Attach hooks
        prog->tk->links.xdp_entry_hook =
            bpf_program__attach(prog->tk->progs.xdp_entry_hook);
        prog->tk->links.xdp_exit_hook =
            bpf_program__attach(prog->tk->progs.xdp_exit_hook);

        if (!prog->tk->links.xdp_entry_hook || !prog->tk->links.xdp_exit_hook) {
            LOG_ERRNO("Failed to hook %s (%d)", prog->name.name, prog->name.id);
            return EXIT_FAILURE;
        }
    }

    if (verbose)
        fprintf(stderr, "Ready to go\n");

    consumer_params.map_fd = bpf_map__fd(xdp_prog(&progs, 0)->tk->maps.trace_perf_map);
    consumer_params.term_eventfd = term_eventfd;
    consumer_params.progs = &progs;

    if (output_filename) {
        if (failed(consumer_run_emit_pcapng(&consumer_params, output_filename)))
            return EXIT_FAILURE;
    } else {
        if (failed(consumer_run_emit_text(&consumer_params)))
            return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

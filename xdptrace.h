#pragma once
#include <stdbool.h>
#include <linux/bpf.h>
#include <sys/types.h>

struct btf;
extern bool verbose;

// type-safe error indication
struct rc { bool success__; };
static inline bool failed(struct rc rc) { return !rc.success__; }
static inline bool succeeded(struct rc rc) { return rc.success__; }
#define FAILURE (struct rc){ false }
#define SUCCESS (struct rc){ true }

// Includes ID to improve error reporting (name might be non-unique)
struct bpf_prog_name {
    const char *name;
    int id;
};

struct bpf_prog_short_name {
    char name[BPF_OBJ_NAME_LEN];
    int id;
};

struct xdp_meta {
    int link_type;
    int pseudo_sz;
    int pseudo_type_id;
};

struct xdp_prog_meta {
    struct xdp_meta entry;
    struct xdp_meta exit;
};

// BPF program name as reported by introspection APIs is limited to 15 chars.
// Find the full name using BTF.  The returned pointer refers to a
// string inside the passed BTF (no copying).
struct rc
bpf_prog_full_name(struct btf *btf, struct bpf_prog_short_name short_name,
                   struct bpf_prog_name *name);

// Parse XDP_METADATA() section for the particular program.
struct rc
parse_xdp_prog_meta(struct btf *btf, struct bpf_prog_name name,
                    struct xdp_prog_meta *meta);

///////////////////////////////////////////////////////////////////////

struct xdp_prog {
    struct bpf_prog_name  name;
    int                   prog_fd;
    struct btf           *btf;

    struct xdp_prog_meta  meta;

    struct trace_kern    *tk;
};

struct consumer_params {
    bool e_flag;
    sigset_t *term_sigs; // the caller MUST block these sigs for termination to work
};

struct rc
consumer_run_emit_pcapng(
    int map_fd, struct xdp_prog *progs,
    const char *output_path, const struct consumer_params *params
);

struct rc
consumer_run_emit_text(
    int map_fd, struct xdp_prog *progs,
    const struct consumer_params *params
);

///////////////////////////////////////////////////////////////////////

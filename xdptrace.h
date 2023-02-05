#pragma once
#include <stdbool.h>
#include <linux/bpf.h>

struct btf;

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
int
bpf_prog_full_name(struct btf *btf, struct bpf_prog_short_name short_name,
                   struct bpf_prog_name *name);

// Parse XDP_METADATA() section for the particular program.
int
parse_xdp_prog_meta(struct btf *btf, struct bpf_prog_name name,
                    struct xdp_prog_meta *meta);

extern bool verbose;
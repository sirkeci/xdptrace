#include "xdptrace.h"

#include <pcap/dlt.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

// BPF program name as reported by introspection APIs is limited to 15 chars.
// Find the full name using BTF.  The returned pointer refers to a
// string inside the passed BTF (no copying).
//
// Even if the name wasn't truncated in the first place, scan BTF
// anyway.  This is to ensure that memory management and requirements on
// the BTF are the same for both truncated and pristine names.
int
bpf_prog_full_name(struct btf *btf, struct bpf_prog_short_name short_name,
                   struct bpf_prog_name *name) {

    size_t len = strlen(short_name.name);
    const char *match = 0;

    for (__u32 i = btf__get_nr_types(btf); i--; ) {

        const struct btf_type *t = btf__type_by_id(btf, i);
        const char *name;

        if (!t || !btf_is_func(t) || !(name = btf__name_by_offset(btf, t->name_off)))
            continue;

        // Prefix mismatch?
        if (strncmp(short_name.name, name, len)) continue;

        // Not a full match and the name wasn't truncated?
        if (name[len] && len != BPF_OBJ_NAME_LEN - 1) continue;

        if (match) {
            fprintf(stderr, "Failed to determine the full name of %s (%d): "
                    "ambiguous prefix, possible matches '%s', '%s'\n",
                    short_name.name, short_name.id, match, name);
            return -1;
        }

        match = name;
    }

    if (!match) {
        fprintf(stderr, "Failed to determine the full name of %s (%d): "
                "no matches found in BTF\n",
                short_name.name, short_name.id);
        return -1;
    }

    name->name = match;
    name->id = short_name.id;
    return 0;
}

// Locate VAR 'xdp_metadata_<progname>' and return the type id
static int
locate_xdp_prog_meta(struct btf *btf, struct bpf_prog_name progname) {
    // locate SEC '.maps.xdp.meta'
    __s32 secid = btf__find_by_name_kind(btf, ".maps.xdp.meta", BTF_KIND_DATASEC);
    const struct btf_type *sect;
    if (secid < 0
        || !(sect = btf__type_by_id(btf, secid))) return -1;

    // iterate through SEC and locate VAR 'xdp_metadata_<progname>'
    struct btf_var_secinfo *si = btf_var_secinfos(sect);
    for (int i = 0; i < btf_vlen(sect); ++i) {
        const struct btf_type *vt = btf__type_by_id(btf, si[i].type);
        const char *name;
        if (!vt || !btf_is_var(vt)
            || !(name = btf__name_by_offset(btf, vt->name_off))) continue;

        static const char prefix[] = {
            'x', 'd', 'p', '_', 'm', 'e', 't', 'a', 'd', 'a', 't', 'a', '_'
        };
        if (!strncmp(name, prefix, sizeof(prefix))
            && !strcmp(progname.name, name + sizeof(prefix))
        ) return vt->type;
    }

    return -1;
}

// Parse uint as encoded by __uint(name, val) macro (bpf/bpf_helpers.h).
// It expands into int (*name) [val], a pointer to array of [val] ints.
static int
meta__uint(const struct btf *btf, const struct btf_member *m, __u32 *val) {
    const struct btf_type *pt = btf__type_by_id(btf, m->type);
    if (!pt || !btf_is_ptr(pt)) return -1;

    const struct btf_type *at = btf__type_by_id(btf, pt->type);

    if (!at || !btf_is_array(at)) return -1;

    *val = btf_array(at)->nelems;
    return 0;
}

// Parse type as encoded by __type(name, val) macro (bpf/bpf_helpers.h).
// It expands into typeof(val) *name, a pointer to val.
static int
meta__type(const struct btf *btf, const struct btf_member *m) {
    const struct btf_type *pt = btf__type_by_id(btf, m->type);
    return pt && btf_is_ptr(pt) ? pt->type : -1;
}

// Parse XDP_METADATA() section for the particular program.
int
parse_xdp_prog_meta(struct btf *btf, struct bpf_prog_name progname,
                    struct xdp_prog_meta *meta) {

    meta->entry.link_type = DLT_EN10MB;
    meta->entry.pseudo_sz = 0;
    meta->entry.pseudo_type_id = -1;
    meta->exit.link_type = DLT_EN10MB;
    meta->exit.pseudo_sz = 0;
    meta->exit.pseudo_type_id = -1;

    // Note irt diagnostics: we trust that the basic structure of BTF is
    // correct (e.g. name offsets are valid).  We still check but don't
    // produce helpful diagnostics if BTF itself is borked.

    int tid = locate_xdp_prog_meta(btf, progname);
    if (tid < 0) {
        // Missing metadata is OK
        return 0;
    }

    const struct btf_type *t = btf__type_by_id(btf, tid);
    if (!t || !btf_is_struct(t)) {
        fprintf(stderr, "Malformed metadata for %s (%d)\n", progname.name, progname.id);
        return -1;
    }

    const struct btf_member *member = btf_members(t);
    for (int i = 0; i < btf_vlen(t); ++i) {
        const char *name = btf__name_by_offset(btf, member[i].name_off);
        if (!name) continue;

        if (!strcmp(name, "link_type")) {
            __u32 link_type;
            if (meta__uint(btf, &member[i], &link_type) != 0) {
                fprintf(stderr, "Error parsing 'link_type' for %s (%d)\n",
                        progname.name, progname.id);
                return -1;
            }
            meta->entry.link_type = link_type;
            continue;
        }

        if (!strcmp(name, "pseudo")) {
            int tid = meta__type(btf, &member[i]);
            __s64 sz;
            if (tid < 0 || (sz = btf__resolve_size(btf, tid)) < 0) {
                fprintf(stderr, "Error parsing 'pseudo' for %s (%d)\n",
                        progname.name, progname.id);
                return -1;
            }
            meta->entry.pseudo_sz = sz;
            meta->entry.pseudo_type_id = tid;
            continue;
        }

        if (verbose) {
            fprintf(stderr, "Unknown attribute '%s' in %s (%d) metadata\n",
                    name, progname.name, progname.id);
        }
    }

    return 0;
}

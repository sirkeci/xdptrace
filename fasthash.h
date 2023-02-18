#pragma once
// "fast-hash is a simple, robust, and efficient general-purpose hash function"
// https://github.com/ztanml/fast-hash
//
// Recent research [1] shows that it is at least 15% faster than Jenkins
// hash (Linux kernel, vpp) in BPF due to ISA lacking bitwize rotate insns.
//
// [1] Fast In-kernel Traffic Sketching in eBPF

#include <linux/bpf.h>

static __always_inline __u64 fh64_mix__(__u64 h) {
    h ^= h >> 23;
    h *= 0x2127599bf4325c37ULL;
    h ^= h >> 47;
    return h;
}

enum {
  fh64_m__ = 0x880355f21e6d1965ULL
};

struct fh64 { __u64 h; };

// Init fh64 state
static __always_inline struct fh64 fh64_init(__u64 seed, __u32 len) {
    return (struct fh64){ seed ^ (len * fh64_m__) };
}

// Update fh64 state with the next 8 bytes of input
static __always_inline struct fh64 fh64_update(struct fh64 state, __u64 data) {
    return (struct fh64){
        (state.h ^ fh64_mix__(data)) * fh64_m__
    };
}

// Produce the final hash value
static __always_inline uint64_t fh64_final(struct fh64 state) {
    return fh64_mix__(state.h);
}

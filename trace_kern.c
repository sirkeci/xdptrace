#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "trace_meta.h"

// Config
const volatile __u32 hook_index; // +0 for fentry, +1 for fexit
const volatile __u32 snap_len;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
} trace_perf_map SEC(".maps");

// (re)definition of kernel data structures, courtesy of xdp-tools
struct net_device {
    /* Structure does not need to contain all entries,
     * as "preserve_access_index" will use BTF to fix this. */
    int ifindex;
    // to extract net namespace see dev_net_set in kernel
    // SO_NETNS_COOKIE ioctl to learn netns cookie
} __attribute__((preserve_access_index));

struct xdp_rxq_info {
    /* Structure does not need to contain all entries,
     * as "preserve_access_index" will use BTF to fix this. */
    struct net_device *dev;
    __u32 queue_index;
} __attribute__((preserve_access_index));

struct xdp_buff {
    void *data;
    void *data_end;
    void *data_meta;
    void *data_hard_start;
    unsigned long handle;
    struct xdp_rxq_info *rxq;
} __attribute__((preserve_access_index));

static __always_inline void
trace_pkt(struct xdp_buff *xdp, __u32 hook_index, int res) {

    void *data_end = (void *)(long)xdp->data_end;
    void *data = (void *)(long)xdp->data;

    if (data >= data_end) return;

    struct trace_meta meta = {
        .hook_index = hook_index,
        .res = res,
        .ifindex = xdp->rxq->dev->ifindex,
        .rx_queue = xdp->rxq->queue_index,
    };

    meta.pkt_len = (__u32)(data_end - data);
    meta.cap_len = meta.pkt_len > snap_len ? snap_len : meta.pkt_len;

    bpf_xdp_output(xdp, &trace_perf_map,
                   ((__u64)meta.cap_len << 32) | BPF_F_CURRENT_CPU,
                   &meta, sizeof(meta));
}


SEC("fentry/xdp_tracce_entry__")
int BPF_PROG(xdp_entry_hook, struct xdp_buff *xdp) {

    // BPF_PROG macro adds context param which we don't use
    // (Actually, the kernel puts *original function's* arguments into a
    //  memory buf and passes us a pointer.  The macro takes care of
    //  properly unpacking the arguments.)
    (void)ctx;

    trace_pkt(xdp, hook_index + 0, 0);
    return 0;
}

SEC("fentry/xdp_trace_exit__")
int BPF_PROG(xdp_exit_hook, struct xdp_buff *xdp, int res) {

    // BPF_PROG macro adds context argument which we don't use
    (void)ctx;

    trace_pkt(xdp, hook_index + 1, res);
    return 0;
}

char _license[] SEC("license") = "GPL";

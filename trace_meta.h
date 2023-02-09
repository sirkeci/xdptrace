#include <linux/if.h>

struct trace_meta {
    __u32 hook_index;
    __u32 res;
    __u32 ifindex;
    __u32 rx_queue;
    __u32 pkt_len;
    __u32 cap_len;
    char if_name[IFNAMSIZ];
};

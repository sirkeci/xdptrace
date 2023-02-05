# xdptrace (prototype)

A tcpdump-like tool, attaches to XDP programs and traces
packets as they traverse a tail-call based pipeline.

The tool depends on the tracee coperation.  Specifically,
cooperating XDP programs must define and invoke
```
int xdp_trace_entry__(struct xdp_md *ctx);
int xdp_trace_exit__(struct xdp_md *ctx, int res);
```
subprograms.

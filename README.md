# Example EBPF Proxy Implementation 

** Dependencies -> Docker, go > 1.17 

This ebpf program was adapted from Cilium's implementation of kube-proxy, but pulled 
out and configured to run separated from Cilium's control plane.

## Compile + run program 

This will automatically use cillium/ebpf to compile the C ebpf program into bytecode
using clang, build go bindings, and attach the program to the `connect4`
syscall in the default cgroup all via a simple go program. 

Simply run 

`make run` 

to spin up a backend pod,  and start the program with the VIP `169.1.1.1` which will 
be proxied to the backend pod by our ebpf program 

To see the logs from the ebpf program run 

`sudo cat /sys/kernel/debug/tracing/trace_pipe`
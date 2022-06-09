# Example EBPF Proxy Implementation 

** Dependencies -> Docker OR Podman
                -> go >= 1.17 
                -> LLVM (`sudo dnf install llvm`)
                -> GLIBC (`sudo dnf install glibc-devel.i686`)
                -> Disable Firewalld (`sudo systemctl disable firewalld`)

This ebpf program was adapted from Cilium's implementation of kube-proxy, but pulled 
out and configured to run separated from Cilium's control plane. 

** ALL CREDIT FOR THE EBPF PROGRAM WRITTEN IN C SHOULD GO TO CILIUM DEVELOPERS **

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

## Licensing 

The user space components of this example are licensed under the [MIT License](/LICENSE). 

The bpf code template (defined in [`cgroup_connect3.c`](/cgroup_connect4.c)) was adapted from 
the bpf templates defined in the [Cilium Project](https://github.com/cilium/cilium) and 
continues to use the same license defined there, i.e the [2-Clause BSD License](/LICENSE-BSD). 
This is confirmed by the [following commit](https://github.com/astoycos/go-ebpf-proxy-example/commit/edef588325a6f9c00c5ae893888917f08243ac70).

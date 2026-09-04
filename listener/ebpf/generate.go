package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip llvm-strip -cflags "-O2 -g -target bpfel" datapath ./bpf/datapath.c -- -I./bpf -I./bpf/include

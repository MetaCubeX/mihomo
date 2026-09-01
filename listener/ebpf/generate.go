package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc /opt/homebrew/Cellar/llvm/23.1.0/bin/clang -strip /opt/homebrew/Cellar/llvm/23.1.0/bin/llvm-strip -cflags "-O2 -g -target bpfel" datapath ./bpf/datapath.c -- -I./bpf -I./bpf/include

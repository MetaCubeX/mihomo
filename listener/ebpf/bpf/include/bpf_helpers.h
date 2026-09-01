#ifndef MIHOMO_EBPF_HELPERS_H
#define MIHOMO_EBPF_HELPERS_H

#include <stdint.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;

struct __sk_buff;

enum {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_RINGBUF = 27,
};

#define TC_ACT_OK 0
#define BPF_F_NO_PREALLOC 1

#endif

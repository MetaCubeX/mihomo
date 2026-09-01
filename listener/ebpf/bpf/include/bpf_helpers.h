#ifndef MIHOMO_EBPF_HELPERS_H
#define MIHOMO_EBPF_HELPERS_H

#include <stdint.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

/* Keep these UAPI context layouts in sync with linux/bpf.h. */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
};

struct bpf_sk_lookup {
	union {
		void *sk;
		__u64 cookie;
	};
	__u32 family;
	__u32 protocol;
	__u32 remote_ip4;
	__u32 remote_ip6[4];
	__u32 remote_port;
	__u32 local_ip4;
	__u32 local_ip6[4];
	__u32 local_port;
	__u32 ingress_ifindex;
};

enum {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_RINGBUF = 27,
};

#define TC_ACT_OK 0
#define SK_PASS 1
#define SK_DROP 0
#define PACKET_HOST 0
#define BPF_F_NO_PREALLOC 1
#define BPF_ANY 0

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *)9;
static long (*bpf_skb_load_bytes)(struct __sk_buff *skb, __u32 offset, void *to, __u32 len) = (void *)26;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)23;
static long (*bpf_redirect_peer)(__u32 ifindex, __u64 flags) = (void *)155;
static long (*bpf_skb_change_type)(struct __sk_buff *skb, __u32 type) = (void *)32;
static long (*bpf_sk_assign)(struct bpf_sk_lookup *ctx, void *sk, __u64 flags) = (void *)124;
static void (*bpf_sk_release)(void *sk) = (void *)86;

#endif

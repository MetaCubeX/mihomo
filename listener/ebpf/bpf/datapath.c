/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "abi.h"
#include "include/bpf_helpers.h"

struct lpm_v4_key { __u32 prefixlen; __u32 addr; };
struct lpm_v6_key { __u32 prefixlen; __u8 addr[16]; };
struct ip6_key { __u8 addr[16]; };

#define MAP(NAME, TYPE, MAX, KEY, VALUE) \
struct { __uint(type, TYPE); __uint(max_entries, MAX); __type(key, KEY); __type(value, VALUE); } NAME SEC(".maps")

MAP(DAE_PARAM, BPF_MAP_TYPE_ARRAY, 1, __u32, struct dae_param);
MAP(BYPASS_SRC_PORTS, BPF_MAP_TYPE_HASH, 256, __u16, __u8);
MAP(BYPASS_DST_PORTS, BPF_MAP_TYPE_HASH, 256, __u16, __u8);
MAP(BYPASS_SRC_IPS, BPF_MAP_TYPE_LPM_TRIE, 1024, struct lpm_v4_key, __u8);
MAP(BYPASS_SRC_IP6S, BPF_MAP_TYPE_LPM_TRIE, 1024, struct lpm_v6_key, __u8);
MAP(BYPASS_DST_IPS, BPF_MAP_TYPE_LPM_TRIE, 1024, struct lpm_v4_key, __u8);
MAP(BYPASS_DST_IP6S, BPF_MAP_TYPE_LPM_TRIE, 1024, struct lpm_v6_key, __u8);
MAP(PROXY_SRC_PORTS, BPF_MAP_TYPE_HASH, 256, __u16, __u8);
MAP(PROXY_DST_PORTS, BPF_MAP_TYPE_HASH, 256, __u16, __u8);
MAP(PROXY_SRC_IPS, BPF_MAP_TYPE_LPM_TRIE, 1024, struct lpm_v4_key, __u8);
MAP(PROXY_SRC_IP6S, BPF_MAP_TYPE_LPM_TRIE, 1024, struct lpm_v6_key, __u8);
MAP(PROXY_DST_IPS, BPF_MAP_TYPE_LPM_TRIE, 1024, struct lpm_v4_key, __u8);
MAP(PROXY_DST_IP6S, BPF_MAP_TYPE_LPM_TRIE, 1024, struct lpm_v6_key, __u8);
MAP(DYNAMIC_BYPASS_DST_IPS, BPF_MAP_TYPE_LRU_HASH, 16384, __u32, __u8);
MAP(DYNAMIC_BYPASS_DST_IP6S, BPF_MAP_TYPE_LRU_HASH, 4096, struct ip6_key, __u8);
MAP(REDIRECT_TRACK, BPF_MAP_TYPE_LRU_HASH, 32768, struct redirect_tuple, struct redirect_entry);
MAP(DIRECT_TRACK, BPF_MAP_TYPE_LRU_HASH, 65536, struct redirect_tuple, struct direct_track_entry);
MAP(LISTEN_SOCKET_MAP, BPF_MAP_TYPE_SOCKMAP, 4, __u32, __u32);
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 262144); } EVENT_RINGBUF SEC(".maps");

SEC("classifier/ingress")
int tc_ingress(struct __sk_buff *skb) {
	(void)skb;
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

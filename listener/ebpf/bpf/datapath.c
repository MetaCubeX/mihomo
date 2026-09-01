/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "abi.h"
#include "include/bpf_helpers.h"

struct lpm_v4_key { __u32 prefixlen; __u32 addr; };
struct lpm_v6_key { __u32 prefixlen; __u8 addr[16]; };
struct ip6_key { __u8 addr[16]; };
struct ethhdr { __u8 dst[6]; __u8 src[6]; __u16 proto; };
struct ipv4hdr { __u8 version_ihl; __u8 tos; __u16 len; __u16 id; __u16 frag; __u8 ttl; __u8 protocol; };
struct ipv6hdr { __u32 version_tc_flow; __u16 payload_len; __u8 next_header; __u8 hop_limit; };

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define IPPROTO_TCP 6
#define SK_TCP4 0
#define SK_TCP6 1

static __u16 ntohs(__u16 value) { return __builtin_bswap16(value); }

#define MAP(NAME, TYPE, MAX, KEY, VALUE) \
struct { __uint(type, TYPE); __uint(max_entries, MAX); __type(key, KEY); __type(value, VALUE); } NAME SEC(".maps")
#define LPM_MAP(NAME, MAX, KEY) \
struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); __uint(max_entries, MAX); __uint(map_flags, BPF_F_NO_PREALLOC); __type(key, KEY); __type(value, __u8); } NAME SEC(".maps")

MAP(DAE_PARAM, BPF_MAP_TYPE_ARRAY, 1, __u32, struct dae_param);
MAP(BYPASS_SRC_PORTS, BPF_MAP_TYPE_HASH, 256, __u16, __u8);
MAP(BYPASS_DST_PORTS, BPF_MAP_TYPE_HASH, 256, __u16, __u8);
LPM_MAP(BYPASS_SRC_IPS, 1024, struct lpm_v4_key);
LPM_MAP(BYPASS_SRC_IP6S, 1024, struct lpm_v6_key);
LPM_MAP(BYPASS_DST_IPS, 1024, struct lpm_v4_key);
LPM_MAP(BYPASS_DST_IP6S, 1024, struct lpm_v6_key);
MAP(PROXY_SRC_PORTS, BPF_MAP_TYPE_HASH, 256, __u16, __u8);
MAP(PROXY_DST_PORTS, BPF_MAP_TYPE_HASH, 256, __u16, __u8);
LPM_MAP(PROXY_SRC_IPS, 1024, struct lpm_v4_key);
LPM_MAP(PROXY_SRC_IP6S, 1024, struct lpm_v6_key);
LPM_MAP(PROXY_DST_IPS, 1024, struct lpm_v4_key);
LPM_MAP(PROXY_DST_IP6S, 1024, struct lpm_v6_key);
MAP(DYNAMIC_BYPASS_DST_IPS, BPF_MAP_TYPE_LRU_HASH, 16384, __u32, __u8);
MAP(DYNAMIC_BYPASS_DST_IP6S, BPF_MAP_TYPE_LRU_HASH, 4096, struct ip6_key, __u8);
MAP(REDIRECT_TRACK, BPF_MAP_TYPE_LRU_HASH, 32768, struct redirect_tuple, struct redirect_entry);
MAP(DIRECT_TRACK, BPF_MAP_TYPE_LRU_HASH, 65536, struct redirect_tuple, struct direct_track_entry);
MAP(LISTEN_SOCKET_MAP, BPF_MAP_TYPE_SOCKMAP, 4, __u32, __u32);
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 262144); } EVENT_RINGBUF SEC(".maps");

static int is_tcp(struct __sk_buff *skb) {
	struct ethhdr eth = {};
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) != 0)
		return 0;
	if (ntohs(eth.proto) == ETH_P_IP) {
		struct ipv4hdr ip = {};
		if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip)) != 0)
			return 0;
		return ip.protocol == IPPROTO_TCP;
	}
	if (ntohs(eth.proto) == ETH_P_IPV6) {
		struct ipv6hdr ip6 = {};
		if (bpf_skb_load_bytes(skb, sizeof(eth), &ip6, sizeof(ip6)) != 0)
			return 0;
		return ip6.next_header == IPPROTO_TCP;
	}
	return 0;
}

// LAN ingress only classifies TCP and transfers it to dae0. Routing policy
// remains in Mihomo after sk_lookup assigns the transparent listener.
SEC("classifier/lan_ingress")
int tc_lan_ingress(struct __sk_buff *skb) {
	__u32 key = 0;
	struct dae_param *param = bpf_map_lookup_elem(&DAE_PARAM, &key);
	if (!param || !param->dae0_ifindex || !is_tcp(skb))
		return TC_ACT_OK;
	// A veth peer only admits frames addressed to its own MAC. Keep the
	// original L3/L4 tuple untouched for transparent socket lookup.
	if (bpf_skb_store_bytes(skb, 0, param->dae0peer_mac, 6, 0) != 0)
		return TC_ACT_OK;
	skb->mark = 0x1dae;
	skb->cb[0] = 0x1dae;
	skb->cb[1] = IPPROTO_TCP;
	return param->use_redirect_peer ? bpf_redirect_peer(param->dae0_ifindex, 0) : bpf_redirect(param->dae0_ifindex, 0);
}

// dae0peer receives the redirected packet in the isolated namespace. Mark
// it local and force PACKET_HOST so policy routing reaches sk_lookup.
SEC("classifier/dae0peer_ingress")
int tc_dae0peer_ingress(struct __sk_buff *skb) {
	// dae0peer is private to this datapath. Mark every packet delivered over
	// it so a redirect helper that clears skb->cb still reaches table 100.
	bpf_skb_change_type(skb, PACKET_HOST);
	skb->mark = 0x1dae;
	return TC_ACT_OK;
}

SEC("sk_lookup/")
int tproxy_sk_lookup(struct bpf_sk_lookup *ctx) {
	__u32 key;
	void *socket;
	if (ctx->protocol != IPPROTO_TCP)
		return SK_PASS;
	if (ctx->family == 2)
		key = SK_TCP4;
	else if (ctx->family == 10)
		key = SK_TCP6;
	else
		return SK_PASS;
	socket = bpf_map_lookup_elem(&LISTEN_SOCKET_MAP, &key);
	if (!socket)
		return SK_PASS;
	if (bpf_sk_assign(ctx, socket, 0) != 0) {
		bpf_sk_release(socket);
		return SK_DROP;
	}
	bpf_sk_release(socket);
	return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";

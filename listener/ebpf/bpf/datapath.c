/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "abi.h"
#include "include/bpf_helpers.h"

struct lpm_v4_key { __u32 prefixlen; __u32 addr; };
struct lpm_v6_key { __u32 prefixlen; __u8 addr[16]; };
struct ip6_key { __u8 addr[16]; };
struct ethhdr { __u8 dst[6]; __u8 src[6]; __u16 proto; };
struct ipv4hdr { __u8 version_ihl; __u8 tos; __u16 len; __u16 id; __u16 frag; __u8 ttl; __u8 protocol; __u16 check; __u32 saddr; __u32 daddr; };
struct ipv6hdr { __u32 version_tc_flow; __u16 payload_len; __u8 next_header; __u8 hop_limit; __u8 saddr[16]; __u8 daddr[16]; };
struct ports { __u16 src; __u16 dst; };

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define SK_TCP4 0
#define SK_TCP6 1
#define SK_UDP4 2
#define SK_UDP6 3
#define UDP_CONN_TIMEOUT_NS 120000000000ULL
#define TRACK_UPDATE_INTERVAL_NS 1000000000ULL

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

static int is_supported_transport(__u8 protocol) {
	return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP;
}

static int direct_track_hit(struct redirect_tuple *tuple, __u8 proto, int pure_syn, int fin_rst) {
	struct direct_track_entry *entry;
	__u64 now, elapsed;
	if (pure_syn)
		return 0;
	entry = bpf_map_lookup_elem(&DIRECT_TRACK, tuple);
	if (!entry)
		return 0;
	now = bpf_ktime_get_ns();
	elapsed = now - entry->last_seen_ns;
	if (proto == IPPROTO_UDP && elapsed > UDP_CONN_TIMEOUT_NS) {
		bpf_map_delete_elem(&DIRECT_TRACK, tuple);
		return 0;
	}
	if (proto == IPPROTO_TCP && fin_rst) {
		bpf_map_delete_elem(&DIRECT_TRACK, tuple);
		return 1;
	}
	if (elapsed > TRACK_UPDATE_INTERVAL_NS) {
		struct direct_track_entry updated = { .last_seen_ns = now, .state = 0 };
		bpf_map_update_elem(&DIRECT_TRACK, tuple, &updated, BPF_ANY);
	}
	return 1;
}

static void direct_track_register(struct redirect_tuple *tuple) {
	struct direct_track_entry entry = { .last_seen_ns = bpf_ktime_get_ns(), .state = 0 };
	bpf_map_update_elem(&DIRECT_TRACK, tuple, &entry, BPF_ANY);
}

static int capture_redirect_reply(struct __sk_buff *skb) {
	struct ethhdr eth = {};
	struct redirect_tuple tuple = {};
	struct redirect_entry entry = {};
	struct ports ports = {};
	__u32 l4offset;
	__u8 flags = 0;
	int dynamic_bypass = 0;
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) != 0)
		return 0;
	if (ntohs(eth.proto) == ETH_P_IP) {
		struct ipv4hdr ip = {};
		if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip)) != 0)
			return 0;
		__u32 ihl = (ip.version_ihl & 0x0f) * 4;
		l4offset = sizeof(eth) + ihl;
		if (ihl < sizeof(ip) || !is_supported_transport(ip.protocol) ||
		    bpf_skb_load_bytes(skb, l4offset, &ports, sizeof(ports)) != 0)
			return 0;
		dynamic_bypass = bpf_map_lookup_elem(&DYNAMIC_BYPASS_DST_IPS, &ip.daddr) != 0;
		__builtin_memcpy(tuple.src_ip, &ip.daddr, sizeof(ip.daddr));
		__builtin_memcpy(tuple.dst_ip, &ip.saddr, sizeof(ip.saddr));
		tuple.src_port = ports.dst;
		tuple.dst_port = ports.src;
		tuple.proto = ip.protocol;
		tuple.ip_version = 4;
	}
	else if (ntohs(eth.proto) == ETH_P_IPV6) {
		struct ipv6hdr ip6 = {};
		if (bpf_skb_load_bytes(skb, sizeof(eth), &ip6, sizeof(ip6)) != 0)
			return 0;
		l4offset = sizeof(eth) + sizeof(ip6);
		if (!is_supported_transport(ip6.next_header) ||
		    bpf_skb_load_bytes(skb, l4offset, &ports, sizeof(ports)) != 0)
			return 0;
		{
			struct ip6_key key = {};
			__builtin_memcpy(key.addr, ip6.daddr, sizeof(key.addr));
			dynamic_bypass = bpf_map_lookup_elem(&DYNAMIC_BYPASS_DST_IP6S, &key) != 0;
		}
		__builtin_memcpy(tuple.src_ip, ip6.daddr, sizeof(ip6.daddr));
		__builtin_memcpy(tuple.dst_ip, ip6.saddr, sizeof(ip6.saddr));
		tuple.src_port = ports.dst;
		tuple.dst_port = ports.src;
		tuple.proto = ip6.next_header;
		tuple.ip_version = 6;
	} else {
		return 0;
	}
	if (tuple.proto == IPPROTO_TCP)
		bpf_skb_load_bytes(skb, l4offset + 13, &flags, sizeof(flags));
	if (bpf_map_lookup_elem(&BYPASS_SRC_PORTS, &ports.src))
		return 2;
	// DNS stays intercepted unless explicitly bypassed as a source service;
	// this matches the reference's forced DNS interception policy.
	if (ntohs(ports.dst) != 53 && bpf_map_lookup_elem(&BYPASS_DST_PORTS, &ports.dst))
		return 2;
	if (direct_track_hit(&tuple, tuple.proto, tuple.proto == IPPROTO_TCP && (flags & 0x12) == 0x02, tuple.proto == IPPROTO_TCP && (flags & 0x05) != 0))
		return 2;
	if (dynamic_bypass) {
		direct_track_register(&tuple);
		return 2;
	}
	entry.ifindex = skb->ifindex;
	__builtin_memcpy(entry.smac, eth.dst, sizeof(entry.smac));
	__builtin_memcpy(entry.dmac, eth.src, sizeof(entry.dmac));
	return bpf_map_update_elem(&REDIRECT_TRACK, &tuple, &entry, BPF_ANY) == 0;
}

static int restore_redirect_reply(struct __sk_buff *skb) {
	struct ethhdr eth = {};
	struct redirect_tuple tuple = {};
	struct ports ports = {};
	struct redirect_entry *entry;
	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) != 0)
		return TC_ACT_OK;
	if (ntohs(eth.proto) == ETH_P_IP) {
		struct ipv4hdr ip = {};
		__u32 ihl;
		if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip)) != 0)
			return TC_ACT_OK;
		ihl = (ip.version_ihl & 0x0f) * 4;
		if (ihl < sizeof(ip) || !is_supported_transport(ip.protocol) ||
		    bpf_skb_load_bytes(skb, sizeof(eth) + ihl, &ports, sizeof(ports)) != 0)
			return TC_ACT_OK;
		__builtin_memcpy(tuple.src_ip, &ip.saddr, sizeof(ip.saddr));
		__builtin_memcpy(tuple.dst_ip, &ip.daddr, sizeof(ip.daddr));
		tuple.src_port = ports.src;
		tuple.dst_port = ports.dst;
		tuple.proto = ip.protocol;
		tuple.ip_version = 4;
	} else if (ntohs(eth.proto) == ETH_P_IPV6) {
		struct ipv6hdr ip6 = {};
		if (bpf_skb_load_bytes(skb, sizeof(eth), &ip6, sizeof(ip6)) != 0 ||
		    !is_supported_transport(ip6.next_header) ||
		    bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(ip6), &ports, sizeof(ports)) != 0)
			return TC_ACT_OK;
		__builtin_memcpy(tuple.src_ip, ip6.saddr, sizeof(ip6.saddr));
		__builtin_memcpy(tuple.dst_ip, ip6.daddr, sizeof(ip6.daddr));
		tuple.src_port = ports.src;
		tuple.dst_port = ports.dst;
		tuple.proto = ip6.next_header;
		tuple.ip_version = 6;
	} else {
		return TC_ACT_OK;
	}
	entry = bpf_map_lookup_elem(&REDIRECT_TRACK, &tuple);
	if (!entry)
		return TC_ACT_OK;
	if (bpf_skb_store_bytes(skb, 0, entry->dmac, sizeof(entry->dmac), 0) != 0 ||
	    bpf_skb_store_bytes(skb, 6, entry->smac, sizeof(entry->smac), 0) != 0)
		return TC_ACT_OK;
	return bpf_redirect(entry->ifindex, 0);
}

// LAN ingress records the L2 return path and transfers TCP/UDP to dae0.
// Routing policy remains in Mihomo after sk_lookup assigns the listener.
SEC("classifier/lan_ingress")
int tc_lan_ingress(struct __sk_buff *skb) {
	__u32 key = 0;
	struct dae_param *param = bpf_map_lookup_elem(&DAE_PARAM, &key);
	if (!param || !param->dae0_ifindex || skb->mark == DAE_BYPASS_MARK ||
	    (param->dae_socket_mark && skb->mark == param->dae_socket_mark))
		return TC_ACT_OK;
	if (capture_redirect_reply(skb) != 1)
		return TC_ACT_OK;
	// A veth peer only admits frames addressed to its own MAC. Keep the
	// original L3/L4 tuple untouched for transparent socket lookup.
	if (bpf_skb_store_bytes(skb, 0, param->dae0peer_mac, 6, 0) != 0)
		return TC_ACT_OK;
	skb->mark = 0x1dae;
	skb->cb[0] = 0x1dae;
	skb->cb[1] = 0;
	return param->use_redirect_peer ? bpf_redirect_peer(param->dae0_ifindex, 0) : bpf_redirect(param->dae0_ifindex, 0);
}

// Replies from the isolated namespace retain the intercepted original
// destination as source. Restore the observed LAN MACs and send them straight
// back to the ingress interface, without a host routing or NAT rule.
SEC("classifier/dae0_ingress")
int tc_dae0_ingress(struct __sk_buff *skb) {
	return restore_redirect_reply(skb);
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
	if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
		return SK_PASS;
	if (ctx->family == 2)
		key = ctx->protocol == IPPROTO_TCP ? SK_TCP4 : SK_UDP4;
	else if (ctx->family == 10)
		key = ctx->protocol == IPPROTO_TCP ? SK_TCP6 : SK_UDP6;
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

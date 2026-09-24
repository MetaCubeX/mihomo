/* SPDX-License-Identifier: GPL-3.0-or-later */
/* New flows are classified once; FLOW_OWNER always wins over destination policy. */
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
#define TC_ACT_SHOT 2
#define BPF_NOEXIST 1
static __u16 ntohs(__u16 v) { return __builtin_bswap16(v); }
#define MAP(N,T,M,K,V) struct { __uint(type,T); __uint(max_entries,M); __type(key,K); __type(value,V); } N SEC(".maps")
#define LPM(N,M,K) struct { __uint(type,BPF_MAP_TYPE_LPM_TRIE); __uint(max_entries,M); __uint(map_flags,BPF_F_NO_PREALLOC); __type(key,K); __type(value,__u8); } N SEC(".maps")

MAP(DAE_PARAM, BPF_MAP_TYPE_ARRAY, 1, __u32, struct dae_param);
MAP(BYPASS_SRC_PORTS, BPF_MAP_TYPE_HASH, 256, __u16, __u8);
MAP(BYPASS_DST_PORTS, BPF_MAP_TYPE_HASH, 256, __u16, __u8);
LPM(BYPASS_SRC_IPS, 65536, struct lpm_v4_key); LPM(BYPASS_SRC_IP6S, 65536, struct lpm_v6_key);
LPM(BYPASS_DST_IPS, 65536, struct lpm_v4_key); LPM(BYPASS_DST_IP6S, 65536, struct lpm_v6_key);
MAP(PROXY_SRC_PORTS, BPF_MAP_TYPE_HASH, 256, __u16, __u8);
MAP(PROXY_DST_PORTS, BPF_MAP_TYPE_HASH, 256, __u16, __u8);
LPM(PROXY_SRC_IPS, 65536, struct lpm_v4_key); LPM(PROXY_SRC_IP6S, 65536, struct lpm_v6_key);
LPM(PROXY_DST_IPS, 65536, struct lpm_v4_key); LPM(PROXY_DST_IP6S, 65536, struct lpm_v6_key);
MAP(DYN_DIRECT4, BPF_MAP_TYPE_LRU_HASH, 16384, __u32, __u8); MAP(DYN_DIRECT6, BPF_MAP_TYPE_LRU_HASH, 4096, struct ip6_key, __u8);
MAP(DYN_PROXY4, BPF_MAP_TYPE_LRU_HASH, 16384, __u32, __u8); MAP(DYN_PROXY6, BPF_MAP_TYPE_LRU_HASH, 4096, struct ip6_key, __u8);
MAP(REDIRECT_TRACK, BPF_MAP_TYPE_LRU_HASH, 32768, struct redirect_tuple, struct redirect_entry);
MAP(FLOW_OWNER, BPF_MAP_TYPE_LRU_HASH, 65536, struct redirect_tuple, struct flow_owner_entry);
MAP(LISTEN_SOCKET_MAP, BPF_MAP_TYPE_SOCKMAP, 4, __u32, __u32);
struct { __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,262144); } EVENT_RINGBUF SEC(".maps");

static int supported(__u8 p) { return p == IPPROTO_TCP || p == IPPROTO_UDP; }
static void reverse(struct redirect_tuple *r, const struct redirect_tuple *t) {
	__builtin_memcpy(r->src_ip,t->dst_ip,16); __builtin_memcpy(r->dst_ip,t->src_ip,16);
	r->src_port=t->dst_port; r->dst_port=t->src_port; r->proto=t->proto; r->ip_version=t->ip_version;
}
static int owner_hit(struct redirect_tuple *t, int close) {
	struct flow_owner_entry *e; struct flow_owner_entry u={}; struct redirect_tuple r={}; __u64 now, age; __u8 owner;
	e=bpf_map_lookup_elem(&FLOW_OWNER,t); if (!e) return 0;
	owner=e->owner;
	now=bpf_ktime_get_ns(); age=now-e->last_seen_ns;
	if (t->proto==IPPROTO_UDP && age>UDP_CONN_TIMEOUT_NS) { bpf_map_delete_elem(&FLOW_OWNER,t); reverse(&r,t); bpf_map_delete_elem(&FLOW_OWNER,&r); return 0; }
	u.last_seen_ns=now; u.owner=owner; if(age>TRACK_UPDATE_INTERVAL_NS) bpf_map_update_elem(&FLOW_OWNER,t,&u,BPF_ANY);
	if(close) { bpf_map_delete_elem(&FLOW_OWNER,t); reverse(&r,t); bpf_map_delete_elem(&FLOW_OWNER,&r); }
	return owner;
}
/* Roll back the first insert if the reverse key cannot be installed. */
static int owner_create(struct redirect_tuple *t, __u8 owner) {
	struct redirect_tuple r={}; struct flow_owner_entry e={.last_seen_ns=bpf_ktime_get_ns(),.owner=owner}; reverse(&r,t);
	if(bpf_map_update_elem(&FLOW_OWNER,t,&e,BPF_NOEXIST)) return -1;
	if(bpf_map_update_elem(&FLOW_OWNER,&r,&e,BPF_NOEXIST)) { bpf_map_delete_elem(&FLOW_OWNER,t); return -1; }
	return 0;
}
static int lpm4(void *m, __u32 a) { struct lpm_v4_key k={.prefixlen=32,.addr=a}; return bpf_map_lookup_elem(m,&k)!=0; }
static int lpm6(void *m, const __u8 *a) { struct lpm_v6_key k={.prefixlen=128}; __builtin_memcpy(k.addr,a,16); return bpf_map_lookup_elem(m,&k)!=0; }
static int proxy_dst(struct redirect_tuple *t, __u32 a4, __u16 port) {
	struct ip6_key k={}; if(bpf_map_lookup_elem(&PROXY_DST_PORTS,&port)) return 1;
	if(t->ip_version==4) return bpf_map_lookup_elem(&DYN_PROXY4,&a4)||lpm4(&PROXY_DST_IPS,a4);
	__builtin_memcpy(k.addr,t->dst_ip,16); return bpf_map_lookup_elem(&DYN_PROXY6,&k)||lpm6(&PROXY_DST_IP6S,t->dst_ip);
}
static int direct_dst(struct redirect_tuple *t, __u32 a4) {
	struct ip6_key k={}; if(t->ip_version==4) return bpf_map_lookup_elem(&DYN_DIRECT4,&a4)||lpm4(&BYPASS_DST_IPS,a4);
	__builtin_memcpy(k.addr,t->dst_ip,16); return bpf_map_lookup_elem(&DYN_DIRECT6,&k)||lpm6(&BYPASS_DST_IP6S,t->dst_ip);
}
static int proxy_src(struct redirect_tuple *t, __u16 port) {
	__u32 a4=0; if(bpf_map_lookup_elem(&PROXY_SRC_PORTS,&port)) return 1;
	if(t->ip_version==4) { __builtin_memcpy(&a4,t->src_ip,4); return lpm4(&PROXY_SRC_IPS,a4); }
	return lpm6(&PROXY_SRC_IP6S,t->src_ip);
}
static int direct_src(struct redirect_tuple *t) {
	__u32 a4=0; if(t->ip_version==4) { __builtin_memcpy(&a4,t->src_ip,4); return lpm4(&BYPASS_SRC_IPS,a4); }
	return lpm6(&BYPASS_SRC_IP6S,t->src_ip);
}
static int track_redirect(struct __sk_buff *skb, const struct ethhdr *eth, struct redirect_tuple *t) {
	struct redirect_tuple r={}; struct redirect_entry e={.ifindex=skb->ifindex}; reverse(&r,t);
	__builtin_memcpy(e.smac,eth->dst,6); __builtin_memcpy(e.dmac,eth->src,6);
	return bpf_map_update_elem(&REDIRECT_TRACK,&r,&e,BPF_ANY)==0;
}
static int restore_redirect_reply(struct __sk_buff *skb) {
	struct ethhdr eth={}; struct redirect_tuple t={}; struct ports p={}; struct redirect_entry *e;
	if(bpf_skb_load_bytes(skb,0,&eth,sizeof(eth))) return TC_ACT_OK;
	if(ntohs(eth.proto)==ETH_P_IP) { struct ipv4hdr ip={}; __u32 ihl;
		if(bpf_skb_load_bytes(skb,sizeof(eth),&ip,sizeof(ip))) return TC_ACT_OK; ihl=(ip.version_ihl&15)*4;
		if(ihl<sizeof(ip)||!supported(ip.protocol)||bpf_skb_load_bytes(skb,sizeof(eth)+ihl,&p,sizeof(p))) return TC_ACT_OK;
		__builtin_memcpy(t.src_ip,&ip.saddr,4); __builtin_memcpy(t.dst_ip,&ip.daddr,4); t.proto=ip.protocol; t.ip_version=4;
	} else if(ntohs(eth.proto)==ETH_P_IPV6) { struct ipv6hdr ip={};
		if(bpf_skb_load_bytes(skb,sizeof(eth),&ip,sizeof(ip))||!supported(ip.next_header)||bpf_skb_load_bytes(skb,sizeof(eth)+sizeof(ip),&p,sizeof(p))) return TC_ACT_OK;
		__builtin_memcpy(t.src_ip,ip.saddr,16); __builtin_memcpy(t.dst_ip,ip.daddr,16); t.proto=ip.next_header; t.ip_version=6;
	} else return TC_ACT_OK;
	t.src_port=p.src; t.dst_port=p.dst; e=bpf_map_lookup_elem(&REDIRECT_TRACK,&t); if(!e) return TC_ACT_OK;
	if(bpf_skb_store_bytes(skb,0,e->dmac,6,0)||bpf_skb_store_bytes(skb,6,e->smac,6,0)) return TC_ACT_OK;
	return bpf_redirect(e->ifindex,0);
}
SEC("classifier/lan_ingress") int tc_lan_ingress(struct __sk_buff *skb) {
	__u32 key=0,a4=0,off; struct dae_param *param=bpf_map_lookup_elem(&DAE_PARAM,&key); struct ethhdr eth={}; struct redirect_tuple t={}; struct ports p={};
	__u8 flags=0, owner; int syn,close;
	if(!param||!param->dae0_ifindex||skb->mark==DAE_BYPASS_MARK||(param->dae_socket_mark&&skb->mark==param->dae_socket_mark)) return TC_ACT_OK;
	if(bpf_skb_load_bytes(skb,0,&eth,sizeof(eth))) return TC_ACT_OK;
	if(ntohs(eth.proto)==ETH_P_IP) { struct ipv4hdr ip={}; __u32 ihl;
		if(bpf_skb_load_bytes(skb,sizeof(eth),&ip,sizeof(ip))) return TC_ACT_OK; ihl=(ip.version_ihl&15)*4; off=sizeof(eth)+ihl;
		if(ihl<sizeof(ip)||!supported(ip.protocol)||bpf_skb_load_bytes(skb,off,&p,sizeof(p))) return TC_ACT_OK; if(param->local_ip&&ip.daddr==param->local_ip) return TC_ACT_OK;
		__builtin_memcpy(t.src_ip,&ip.saddr,4); __builtin_memcpy(t.dst_ip,&ip.daddr,4); t.proto=ip.protocol;t.ip_version=4;a4=ip.daddr;
	} else if(ntohs(eth.proto)==ETH_P_IPV6) { struct ipv6hdr ip={}; off=sizeof(eth)+sizeof(ip);
		if(bpf_skb_load_bytes(skb,sizeof(eth),&ip,sizeof(ip))||!supported(ip.next_header)||bpf_skb_load_bytes(skb,off,&p,sizeof(p))) return TC_ACT_OK;
		__builtin_memcpy(t.src_ip,ip.saddr,16); __builtin_memcpy(t.dst_ip,ip.daddr,16);t.proto=ip.next_header;t.ip_version=6;
	} else return TC_ACT_OK;
	t.src_port=p.src;t.dst_port=p.dst; if(t.proto==IPPROTO_TCP) bpf_skb_load_bytes(skb,off+13,&flags,1);
	/* DNS/host management bypass is intentionally before policy ownership. */
	if(bpf_map_lookup_elem(&BYPASS_SRC_PORTS,&p.src)||bpf_map_lookup_elem(&BYPASS_DST_PORTS,&p.dst)) return TC_ACT_OK;
	syn=t.proto==IPPROTO_TCP&&(flags&0x12)==0x02; close=t.proto==IPPROTO_TCP&&(flags&0x05)!=0; owner=owner_hit(&t,close);
	if(!owner) {
		/* A non-SYN packet without state must not be reclassified by a fresh IP entry. */
		if(t.proto==IPPROTO_TCP&&!syn) return TC_ACT_SHOT;
		owner=FLOW_OWNER_MIHOMO;
		if(param->direct_offload_enabled&&!proxy_src(&t,p.src)&&!proxy_dst(&t,a4,p.dst)&&(direct_src(&t)||direct_dst(&t,a4))) owner=FLOW_OWNER_DIRECT;
		if(owner_create(&t,owner)) return TC_ACT_SHOT;
	}
	if(owner==FLOW_OWNER_DIRECT) return TC_ACT_OK;
	if(!track_redirect(skb,&eth,&t)||bpf_skb_store_bytes(skb,0,param->dae0peer_mac,6,0)) return TC_ACT_SHOT;
	skb->mark=0x1dae;skb->cb[0]=0x1dae;skb->cb[1]=0; return param->use_redirect_peer?bpf_redirect_peer(param->dae0_ifindex,0):bpf_redirect(param->dae0_ifindex,0);
}
SEC("classifier/dae0_ingress") int tc_dae0_ingress(struct __sk_buff *skb) { return restore_redirect_reply(skb); }
SEC("classifier/dae0peer_ingress") int tc_dae0peer_ingress(struct __sk_buff *skb) { bpf_skb_change_type(skb,PACKET_HOST);skb->mark=0x1dae;return TC_ACT_OK; }
SEC("sk_lookup/") int tproxy_sk_lookup(struct bpf_sk_lookup *ctx) { __u32 key;void *s;
	if(ctx->protocol!=IPPROTO_TCP&&ctx->protocol!=IPPROTO_UDP) return SK_PASS; if(ctx->family==2) key=ctx->protocol==IPPROTO_TCP?SK_TCP4:SK_UDP4; else if(ctx->family==10) key=ctx->protocol==IPPROTO_TCP?SK_TCP6:SK_UDP6;else return SK_PASS;
	s=bpf_map_lookup_elem(&LISTEN_SOCKET_MAP,&key);if(!s)return SK_PASS;if(bpf_sk_assign(ctx,s,0)){bpf_sk_release(s);return SK_DROP;}bpf_sk_release(s);return SK_PASS; }
char LICENSE[] SEC("license")="GPL";

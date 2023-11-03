#include <stdint.h>
#include <stdbool.h>
//#include <linux/types.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
//#include <linux/if_packet.h>
//#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
//#include <linux/udp.h>

#include <linux/pkt_cls.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_PROTO_OFF (ETH_HLEN + offsetof(struct iphdr, protocol))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define TCP_SRC_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define TCP_DST_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
//#define UDP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))
//#define UDP_SRC_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))
//#define UDP_DST_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define IS_PSEUDO 0x10

struct origin_info {
    __be32 ip;
    __be16 port;
    __u16  pad;
};

struct origin_info *origin_info_unused __attribute__((unused));

struct redir_info {
    __be32 sip;
    __be32 dip;
    __be16 sport;
    __be16 dport;
};

struct redir_info *redir_info_unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct redir_info);
    __type(value, struct origin_info);
    __uint(max_entries, 65535);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pair_original_dst_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 3);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} redir_params_map SEC(".maps");

static __always_inline int rewrite_ip(struct __sk_buff *skb, __be32 new_ip, bool is_dest) {
    int ret, off = 0, flags = IS_PSEUDO;
    __be32 old_ip;

    if (is_dest)
        ret = bpf_skb_load_bytes(skb, IP_DST_OFF, &old_ip, 4);
    else
        ret = bpf_skb_load_bytes(skb, IP_SRC_OFF, &old_ip, 4);

    if (ret < 0) {
        return ret;
    }

    off = TCP_CSUM_OFF;
//    __u8 proto;
//
//    ret = bpf_skb_load_bytes(skb, IP_PROTO_OFF, &proto, 1);
//    if (ret < 0) {
//        return BPF_DROP;
//    }
//
//    switch (proto) {
//    case IPPROTO_TCP:
//        off = TCP_CSUM_OFF;
//        break;
//
//    case IPPROTO_UDP:
//        off = UDP_CSUM_OFF;
//        flags |= BPF_F_MARK_MANGLED_0;
//        break;
//
//    case IPPROTO_ICMPV6:
//        off = offsetof(struct icmp6hdr, icmp6_cksum);
//        break;
//    }
//
//    if (off) {
    ret = bpf_l4_csum_replace(skb, off, old_ip, new_ip, flags | sizeof(new_ip));
    if (ret < 0) {
        return ret;
    }
//    }

    ret = bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
    if (ret < 0) {
        return ret;
    }

    if (is_dest)
        ret = bpf_skb_store_bytes(skb, IP_DST_OFF, &new_ip, sizeof(new_ip), 0);
    else
        ret = bpf_skb_store_bytes(skb, IP_SRC_OFF, &new_ip, sizeof(new_ip), 0);

    if (ret < 0) {
        return ret;
    }

    return 1;
}

static __always_inline int rewrite_port(struct __sk_buff *skb, __be16 new_port, bool is_dest) {
    int ret, off = 0;
    __be16 old_port;

    if (is_dest)
        ret = bpf_skb_load_bytes(skb, TCP_DST_OFF, &old_port, 2);
    else
        ret = bpf_skb_load_bytes(skb, TCP_SRC_OFF, &old_port, 2);

    if (ret < 0) {
        return ret;
    }

    off = TCP_CSUM_OFF;

    ret = bpf_l4_csum_replace(skb, off, old_port, new_port, sizeof(new_port));
    if (ret < 0) {
        return ret;
    }

    if (is_dest)
        ret = bpf_skb_store_bytes(skb, TCP_DST_OFF, &new_port, sizeof(new_port), 0);
    else
        ret = bpf_skb_store_bytes(skb, TCP_SRC_OFF, &new_port, sizeof(new_port), 0);

    if (ret < 0) {
        return ret;
    }

    return 1;
}

static __always_inline bool is_lan_ip(__be32 addr) {
    if (addr == 0xffffffff)
        return true;

    __u8 fist = (__u8)(addr & 0xff);

    if (fist == 127 || fist == 10)
        return true;

    __u8 second = (__u8)((addr >> 8) & 0xff);

    if (fist == 172 && second >= 16 && second <= 31)
        return true;

    if (fist == 192 && second == 168)
        return true;

    return false;
}

SEC("tc_mihomo_auto_redir_ingress")
int tc_redir_ingress_func(struct __sk_buff *skb) {
    void *data          = (void *)(long)skb->data;
    void *data_end      = (void *)(long)skb->data_end;
    struct ethhdr *eth  = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u32 key = 0, *route_index, *redir_ip, *redir_port;

    route_index = bpf_map_lookup_elem(&redir_params_map, &key);
    if (!route_index)
        return TC_ACT_OK;

    if (iph->protocol == IPPROTO_ICMP && *route_index != 0)
        return bpf_redirect(*route_index, 0);

    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
        return TC_ACT_SHOT;

    key = 1;
    redir_ip = bpf_map_lookup_elem(&redir_params_map, &key);
    if (!redir_ip)
        return TC_ACT_OK;

    key = 2;
    redir_port = bpf_map_lookup_elem(&redir_params_map, &key);
    if (!redir_port)
        return TC_ACT_OK;

    __be32 new_ip   = bpf_htonl(*redir_ip);
    __be16 new_port = bpf_htonl(*redir_port) >> 16;
    __be32 old_ip   = iph->daddr;
    __be16 old_port = tcph->dest;

    if (old_ip == new_ip || is_lan_ip(old_ip) || bpf_ntohs(old_port) == 53) {
        return TC_ACT_OK;
    }

    struct redir_info p_key = {
        .sip = iph->saddr,
        .sport = tcph->source,
        .dip = new_ip,
        .dport = new_port,
    };

    if (tcph->syn && !tcph->ack) {
        struct origin_info origin = {
            .ip = old_ip,
            .port = old_port,
        };

        bpf_map_update_elem(&pair_original_dst_map, &p_key, &origin, BPF_NOEXIST);

        if (rewrite_ip(skb, new_ip, true) < 0) {
            return TC_ACT_SHOT;
        }

        if (rewrite_port(skb, new_port, true) < 0) {
            return TC_ACT_SHOT;
        }
    } else {
        struct origin_info *origin = bpf_map_lookup_elem(&pair_original_dst_map, &p_key);
        if (!origin) {
            return TC_ACT_OK;
        }

        if (rewrite_ip(skb, new_ip, true) < 0) {
            return TC_ACT_SHOT;
        }

        if (rewrite_port(skb, new_port, true) < 0) {
            return TC_ACT_SHOT;
        }
    }

    return TC_ACT_OK;
}

SEC("tc_mihomo_auto_redir_egress")
int tc_redir_egress_func(struct __sk_buff *skb) {
    void *data          = (void *)(long)skb->data;
    void *data_end      = (void *)(long)skb->data_end;
    struct ethhdr *eth  = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    __u32 key = 0, *redir_ip, *redir_port; // *mihomo_mark

//    mihomo_mark = bpf_map_lookup_elem(&redir_params_map, &key);
//    if (mihomo_mark && *mihomo_mark != 0 && *mihomo_mark == skb->mark)
//        return TC_ACT_OK;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
        return TC_ACT_SHOT;

    key = 1;
    redir_ip = bpf_map_lookup_elem(&redir_params_map, &key);
    if (!redir_ip)
        return TC_ACT_OK;

    key = 2;
    redir_port = bpf_map_lookup_elem(&redir_params_map, &key);
    if (!redir_port)
        return TC_ACT_OK;

    __be32 new_ip   = bpf_htonl(*redir_ip);
    __be16 new_port = bpf_htonl(*redir_port) >> 16;
    __be32 old_ip   = iph->saddr;
    __be16 old_port = tcph->source;

    if (old_ip != new_ip || old_port != new_port) {
        return TC_ACT_OK;
    }

    struct redir_info p_key = {
        .sip = iph->daddr,
        .sport = tcph->dest,
        .dip = iph->saddr,
        .dport = tcph->source,
    };

    struct origin_info *origin = bpf_map_lookup_elem(&pair_original_dst_map, &p_key);
    if (!origin) {
        return TC_ACT_OK;
    }

    if (tcph->fin && tcph->ack) {
        bpf_map_delete_elem(&pair_original_dst_map, &p_key);
    }

    if (rewrite_ip(skb, origin->ip, false) < 0) {
        return TC_ACT_SHOT;
    }

    if (rewrite_port(skb, origin->port, false) < 0) {
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

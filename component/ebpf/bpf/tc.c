#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
//#include <linux/tcp.h>
//#include <linux/udp.h>
#include <linux/pkt_cls.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tc_params_map SEC(".maps");

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

SEC("tc_mihomo_redirect_to_tun")
int tc_tun_func(struct __sk_buff *skb) {
    void *data          = (void *)(long)skb->data;
    void *data_end      = (void *)(long)skb->data_end;
    struct ethhdr *eth  = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto == bpf_htons(ETH_P_ARP))
        return TC_ACT_OK;

    __u32 key = 0, *mihomo_mark, *tun_ifindex;

    mihomo_mark = bpf_map_lookup_elem(&tc_params_map, &key);
    if (!mihomo_mark)
        return TC_ACT_OK;

    if (skb->mark == *mihomo_mark)
        return TC_ACT_OK;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return TC_ACT_OK;

        if (iph->protocol == IPPROTO_ICMP)
            return TC_ACT_OK;

        __be32 daddr = iph->daddr;

        if (is_lan_ip(daddr))
            return TC_ACT_OK;

//        if (iph->protocol == IPPROTO_TCP) {
//            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
//            if ((void *)(tcph + 1) > data_end)
//                return TC_ACT_OK;
//
//            __u16 source = bpf_ntohs(tcph->source);
//            if (source == 22 || source == 80 || source == 443 || source == 8080 || source == 8443 || source == 9090 || (source >= 7890 && source <= 7895))
//                return TC_ACT_OK;
//        } else if (iph->protocol == IPPROTO_UDP) {
//            struct udphdr *udph = (struct udphdr *)(iph + 1);
//            if ((void *)(udph + 1) > data_end)
//                return TC_ACT_OK;
//
//            __u16 source = bpf_ntohs(udph->source);
//            if (source == 53 || (source >= 135 && source <= 139))
//                return TC_ACT_OK;
//        }
    }

    key = 1;
    tun_ifindex = bpf_map_lookup_elem(&tc_params_map, &key);
    if (!tun_ifindex)
        return TC_ACT_OK;

    //return bpf_redirect(*tun_ifindex, BPF_F_INGRESS); // __bpf_rx_skb
    return bpf_redirect(*tun_ifindex, 0); // __bpf_tx_skb / __dev_xmit_skb
}

char _license[] SEC("license") = "GPL";

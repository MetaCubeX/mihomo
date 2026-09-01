/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Shared Mihomo/Clash Premium eBPF ABI, version 1.
 * Reference: CHKayanami/clash-rs@f1a9107e010b01da541af24f471409a2bb1bd2a6
 * (clash-ebpf-common/src/{lib.rs,conn.rs,event.rs}).
 */
#ifndef MIHOMO_EBPF_ABI_H
#define MIHOMO_EBPF_ABI_H

#include <stdint.h>

#define MIHOMO_EBPF_ABI_VERSION 1u
#define DAE_TPROXY_MARK 0x1daeu
#define DAE_BYPASS_MARK 0x2daeu

struct dae_param {
	uint32_t tproxy_port;
	uint32_t dae0_ifindex;
	uint32_t wan_ifindex;
	uint8_t dae0peer_mac[6];
	uint8_t use_redirect_peer;
	uint8_t proxy_local;
	uint32_t dae_socket_mark;
	uint32_t control_plane_pid;
	uint32_t local_ip;
	uint8_t has_proxy_src_ips;
	uint8_t has_proxy_dst_ips;
	uint8_t has_proxy_src_ports;
	uint8_t has_proxy_dst_ports;
	uint8_t direct_offload_enabled;
	uint8_t has_proxy_processes;
	uint8_t has_bypass_processes;
	uint8_t has_bypass_dscps;
	uint8_t has_bypass_fwmarks;
	uint8_t pad1[3];
};

/* IP bytes and transport ports are network byte order; flags are host byte order. */
struct redirect_tuple {
	uint8_t src_ip[16];
	uint8_t dst_ip[16];
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t proto;
	uint8_t ip_version;
	uint8_t pad[2];
};

struct redirect_entry {
	uint32_t ifindex;
	uint8_t from_wan;
	uint8_t pad0[3];
	uint8_t smac[6];
	uint8_t dmac[6];
};

struct direct_track_entry {
	uint64_t last_seen_ns;
	uint8_t state;
	uint8_t pad[7];
};

struct dae_event {
	uint64_t timestamp_ns;
	uint32_t type;
	uint32_t pid;
	uint8_t pname[16];
	uint8_t outbound;
	uint8_t l4proto;
	uint8_t pad[2];
	uint32_t sip[4];
	uint32_t dip[4];
	uint16_t sport;
	uint16_t dport;
};

#endif

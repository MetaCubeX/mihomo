package ebpf

import "unsafe"

const (
	ABIVersion      uint32 = 2
	TPROXYMark      uint32 = 0x1dae
	BypassMark      uint32 = 0x2dae
	FlowOwnerDirect uint8  = 1
	FlowOwnerMihomo uint8  = 2
)

// DaeParam is map DAE_PARAM's sole value. Multi-byte scalar fields use host
// byte order; packet addresses and ports belong to RedirectTuple instead.
type DaeParam struct {
	TPROXYPort           uint32
	DAE0Ifindex          uint32
	WANIfindex           uint32
	DAE0PeerMAC          [6]uint8
	UseRedirectPeer      uint8
	ProxyLocal           uint8
	DAESocketMark        uint32
	ControlPlanePID      uint32
	LocalIP              uint32
	HasProxySrcIPs       uint8
	HasProxyDstIPs       uint8
	HasProxySrcPorts     uint8
	HasProxyDstPorts     uint8
	DirectOffloadEnabled uint8
	HasProxyProcesses    uint8
	HasBypassProcesses   uint8
	HasBypassDSCPs       uint8
	HasBypassFWMarks     uint8
	Pad1                 [3]uint8
}

// RedirectTuple is the flow key for REDIRECT_TRACK and FLOW_OWNER. IP
// bytes and ports are network byte order; Proto is the IP protocol number.
type RedirectTuple struct {
	SrcIP     [16]uint8
	DstIP     [16]uint8
	SrcPort   uint16
	DstPort   uint16
	Proto     uint8
	IPVersion uint8
	Pad       [2]uint8
}

type RedirectEntry struct {
	Ifindex   uint32
	FromWAN   uint8
	Pad0      [3]uint8
	SourceMAC [6]uint8
	DestMAC   [6]uint8
}

// FlowOwnerEntry pins an accepted flow to one data plane. Destination policy
// is intentionally not part of this value: it may only affect future flows.
type FlowOwnerEntry struct {
	LastSeenNS uint64
	Owner      uint8
	Pad        [7]uint8
}

type Event struct {
	TimestampNS uint64
	Type        uint32
	PID         uint32
	ProcessName [16]uint8
	Outbound    uint8
	L4Proto     uint8
	Pad         [2]uint8
	SourceIP    [4]uint32
	DestIP      [4]uint32
	SourcePort  uint16
	DestPort    uint16
}

type MapSpec struct {
	Name       string
	Type       string
	MaxEntries uint32
	KeySize    uintptr
	ValueSize  uintptr
}

var ABIMaps = []MapSpec{
	{"DAE_PARAM", "array", 1, 4, unsafe.Sizeof(DaeParam{})},
	{"BYPASS_SRC_PORTS", "hash", 256, 2, 1},
	{"BYPASS_DST_PORTS", "hash", 256, 2, 1},
	{"BYPASS_SRC_IPS", "lpm_trie", 65536, 8, 1},
	{"BYPASS_SRC_IP6S", "lpm_trie", 65536, 20, 1},
	{"BYPASS_DST_IPS", "lpm_trie", 65536, 8, 1},
	{"BYPASS_DST_IP6S", "lpm_trie", 65536, 20, 1},
	{"PROXY_SRC_PORTS", "hash", 256, 2, 1},
	{"PROXY_DST_PORTS", "hash", 256, 2, 1},
	{"PROXY_SRC_IPS", "lpm_trie", 65536, 8, 1},
	{"PROXY_SRC_IP6S", "lpm_trie", 65536, 20, 1},
	{"PROXY_DST_IPS", "lpm_trie", 65536, 8, 1},
	{"PROXY_DST_IP6S", "lpm_trie", 65536, 20, 1},
	{"DYN_DIRECT4", "lru_hash", 16384, 4, 1},
	{"DYN_DIRECT6", "lru_hash", 4096, 16, 1},
	{"DYN_PROXY4", "lru_hash", 16384, 4, 1},
	{"DYN_PROXY6", "lru_hash", 4096, 16, 1},
	{"REDIRECT_TRACK", "lru_hash", 32768, unsafe.Sizeof(RedirectTuple{}), unsafe.Sizeof(RedirectEntry{})},
	{"FLOW_OWNER", "lru_hash", 65536, unsafe.Sizeof(RedirectTuple{}), unsafe.Sizeof(FlowOwnerEntry{})},
	{"LISTEN_SOCKET_MAP", "sockmap", 4, 4, 4},
	{"EVENT_RINGBUF", "ringbuf", 262144, 0, 0},
}

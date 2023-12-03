//go:build linux

package redir

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"

	"github.com/metacubex/mihomo/component/ebpf/byteorder"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../bpf/redir.c

const (
	mapKey1 uint32 = 0
	mapKey2 uint32 = 1
	mapKey3 uint32 = 2
)

type EBpfRedirect struct {
	objs         io.Closer
	originMap    *ebpf.Map
	qdisc        netlink.Qdisc
	filter       netlink.Filter
	filterEgress netlink.Filter

	ifName    string
	ifIndex   int
	ifMark    uint32
	rtIndex   uint32
	redirIp   uint32
	redirPort uint16

	bpfPath string
}

func NewEBpfRedirect(ifName string, ifIndex int, ifMark uint32, routeIndex uint32, redirAddrPort netip.AddrPort) *EBpfRedirect {
	return &EBpfRedirect{
		ifName:    ifName,
		ifIndex:   ifIndex,
		ifMark:    ifMark,
		rtIndex:   routeIndex,
		redirIp:   binary.BigEndian.Uint32(redirAddrPort.Addr().AsSlice()),
		redirPort: redirAddrPort.Port(),
	}
}

func (e *EBpfRedirect) Start() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memory lock: %w", err)
	}

	e.bpfPath = filepath.Join(C.BpfFSPath, e.ifName)
	if err := os.MkdirAll(e.bpfPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create bpf fs subpath: %w", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: e.bpfPath,
		},
	}); err != nil {
		e.Close()
		return fmt.Errorf("loading objects: %w", err)
	}

	e.objs = &objs
	e.originMap = objs.bpfMaps.PairOriginalDstMap

	if err := objs.bpfMaps.RedirParamsMap.Update(mapKey1, e.rtIndex, ebpf.UpdateAny); err != nil {
		e.Close()
		return fmt.Errorf("storing objects: %w", err)
	}

	if err := objs.bpfMaps.RedirParamsMap.Update(mapKey2, e.redirIp, ebpf.UpdateAny); err != nil {
		e.Close()
		return fmt.Errorf("storing objects: %w", err)
	}

	if err := objs.bpfMaps.RedirParamsMap.Update(mapKey3, uint32(e.redirPort), ebpf.UpdateAny); err != nil {
		e.Close()
		return fmt.Errorf("storing objects: %w", err)
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: e.ifIndex,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	e.qdisc = qdisc

	if err := netlink.QdiscAdd(qdisc); err != nil {
		if os.IsExist(err) {
			_ = netlink.QdiscDel(qdisc)
			err = netlink.QdiscAdd(qdisc)
		}

		if err != nil {
			e.Close()
			return fmt.Errorf("cannot add clsact qdisc: %w", err)
		}
	}

	filterAttrs := netlink.FilterAttrs{
		LinkIndex: e.ifIndex,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_IP,
		Priority:  0,
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           objs.bpfPrograms.TcRedirIngressFunc.FD(),
		Name:         "mihomo-redir-ingress-" + e.ifName,
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		e.Close()
		return fmt.Errorf("cannot attach ebpf object to filter ingress: %w", err)
	}

	e.filter = filter

	filterAttrsEgress := netlink.FilterAttrs{
		LinkIndex: e.ifIndex,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_IP,
		Priority:  0,
	}

	filterEgress := &netlink.BpfFilter{
		FilterAttrs:  filterAttrsEgress,
		Fd:           objs.bpfPrograms.TcRedirEgressFunc.FD(),
		Name:         "mihomo-redir-egress-" + e.ifName,
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filterEgress); err != nil {
		e.Close()
		return fmt.Errorf("cannot attach ebpf object to filter egress: %w", err)
	}

	e.filterEgress = filterEgress

	return nil
}

func (e *EBpfRedirect) Close() {
	if e.filter != nil {
		_ = netlink.FilterDel(e.filter)
	}
	if e.filterEgress != nil {
		_ = netlink.FilterDel(e.filterEgress)
	}
	if e.qdisc != nil {
		_ = netlink.QdiscDel(e.qdisc)
	}
	if e.objs != nil {
		_ = e.objs.Close()
	}
	_ = os.Remove(filepath.Join(e.bpfPath, "redir_params_map"))
	_ = os.Remove(filepath.Join(e.bpfPath, "pair_original_dst_map"))
}

func (e *EBpfRedirect) Lookup(srcAddrPort netip.AddrPort) (socks5.Addr, error) {
	rAddr := srcAddrPort.Addr().Unmap()
	if rAddr.Is6() {
		return nil, fmt.Errorf("remote address is ipv6")
	}

	srcIp := binary.BigEndian.Uint32(rAddr.AsSlice())
	scrPort := srcAddrPort.Port()

	key := bpfRedirInfo{
		Sip:   byteorder.HostToNetwork32(srcIp),
		Sport: byteorder.HostToNetwork16(scrPort),
		Dip:   byteorder.HostToNetwork32(e.redirIp),
		Dport: byteorder.HostToNetwork16(e.redirPort),
	}

	origin := bpfOriginInfo{}

	err := e.originMap.Lookup(key, &origin)
	if err != nil {
		return nil, err
	}

	addr := make([]byte, net.IPv4len+3)
	addr[0] = socks5.AtypIPv4

	binary.BigEndian.PutUint32(addr[1:1+net.IPv4len], byteorder.NetworkToHost32(origin.Ip))               // big end
	binary.BigEndian.PutUint16(addr[1+net.IPv4len:3+net.IPv4len], byteorder.NetworkToHost16(origin.Port)) // big end
	return addr, nil
}

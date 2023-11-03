//go:build linux

package tc

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../bpf/tc.c

const (
	mapKey1 uint32 = 0
	mapKey2 uint32 = 1
)

type EBpfTC struct {
	objs   io.Closer
	qdisc  netlink.Qdisc
	filter netlink.Filter

	ifName     string
	ifIndex    int
	ifMark     uint32
	tunIfIndex uint32

	bpfPath string
}

func NewEBpfTc(ifName string, ifIndex int, ifMark uint32, tunIfIndex uint32) *EBpfTC {
	return &EBpfTC{
		ifName:     ifName,
		ifIndex:    ifIndex,
		ifMark:     ifMark,
		tunIfIndex: tunIfIndex,
	}
}

func (e *EBpfTC) Start() error {
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

	if err := objs.bpfMaps.TcParamsMap.Update(mapKey1, e.ifMark, ebpf.UpdateAny); err != nil {
		e.Close()
		return fmt.Errorf("storing objects: %w", err)
	}

	if err := objs.bpfMaps.TcParamsMap.Update(mapKey2, e.tunIfIndex, ebpf.UpdateAny); err != nil {
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
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           objs.bpfPrograms.TcTunFunc.FD(),
		Name:         "mihomo-tc-" + e.ifName,
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		e.Close()
		return fmt.Errorf("cannot attach ebpf object to filter: %w", err)
	}

	e.filter = filter

	return nil
}

func (e *EBpfTC) Close() {
	if e.filter != nil {
		_ = netlink.FilterDel(e.filter)
	}
	if e.qdisc != nil {
		_ = netlink.QdiscDel(e.qdisc)
	}
	if e.objs != nil {
		_ = e.objs.Close()
	}
	_ = os.Remove(filepath.Join(e.bpfPath, "tc_params_map"))
}

func (e *EBpfTC) Lookup(_ netip.AddrPort) (socks5.Addr, error) {
	return nil, fmt.Errorf("not supported")
}

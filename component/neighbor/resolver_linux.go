//go:build linux && !android

package neighbor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"syscall"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/socket"
	"golang.org/x/sys/unix"
)

const Supported = true

type linuxBackend struct {
	conn     netlinkSocket
	sequence uint32
	buffer   []byte
}

type netlinkSocket interface {
	Recvmsg(context.Context, []byte, []byte, int) (int, int, int, unix.Sockaddr, error)
	Sendto(context.Context, []byte, int, unix.Sockaddr) error
	Close() error
}

func openBackend() (backend, error) {
	c, err := socket.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE, "mihomo-neighbor", nil)
	if err != nil {
		return nil, err
	}
	err = c.Bind(&unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1<<(unix.RTNLGRP_NEIGH-1) | 1<<(unix.RTNLGRP_LINK-1) | 1<<(unix.RTNLGRP_IPV4_IFADDR-1) | 1<<(unix.RTNLGRP_IPV6_IFADDR-1)})
	if err != nil {
		c.Close()
		return nil, err
	}
	// A larger queue reduces overflows; failure is harmless because ENOBUFS
	// still invalidates the cache and triggers a fresh subscription and dump.
	_ = c.SetsockoptInt(unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	return &linuxBackend{conn: c, buffer: make([]byte, 1<<20)}, nil
}

func (b *linuxBackend) Close() error { return b.conn.Close() }

func (b *linuxBackend) receive(ctx context.Context) ([]syscall.NetlinkMessage, error) {
	n, _, flags, from, err := b.conn.Recvmsg(ctx, b.buffer, nil, 0)
	if err != nil {
		return nil, err
	}
	if flags&unix.MSG_TRUNC != 0 {
		return nil, errors.New("truncated neighbor notification")
	}
	if addr, ok := from.(*unix.SockaddrNetlink); !ok || addr.Pid != 0 {
		return nil, errors.New("neighbor notification was not sent by the kernel")
	}
	messages, err := syscall.ParseNetlinkMessage(b.buffer[:n])
	if err != nil {
		return nil, err
	}
	for _, m := range messages {
		if err := checkMessage(m); err != nil {
			return nil, err
		}
	}
	return messages, nil
}

func checkMessage(m syscall.NetlinkMessage) error {
	if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
		return errors.New("neighbor dump interrupted")
	}
	if m.Header.Type == unix.NLMSG_OVERRUN {
		return errors.New("neighbor notifications lost")
	}
	if m.Header.Type == unix.NLMSG_ERROR || m.Header.Type == unix.NLMSG_DONE {
		if m.Header.Type == unix.NLMSG_DONE && len(m.Data) == 0 {
			return nil
		}
		if len(m.Data) < 4 {
			return errors.New("short netlink error message")
		}
		if errno := nlenc.Int32(m.Data[:4]); errno != 0 {
			return syscall.Errno(-errno)
		}
	}
	return nil
}

func (b *linuxBackend) dump(ctx context.Context, kind uint16, data []byte, t *table) (changed bool, err error) {
	b.sequence++
	request := netlink.Message{Header: netlink.Header{
		Type: netlink.HeaderType(kind), Flags: netlink.Request | netlink.Dump, Sequence: b.sequence,
	}, Data: data}
	request.Header.Length = uint32(unix.NLMSG_HDRLEN + len(data))
	wire, err := request.MarshalBinary()
	if err != nil {
		return false, err
	}
	if err = b.conn.Sendto(ctx, wire, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return false, err
	}
	for {
		messages, err := b.receive(ctx)
		if err != nil {
			return false, err
		}
		done := false
		for _, m := range messages {
			if m.Header.Seq != 0 && m.Header.Seq != b.sequence {
				return false, errors.New("unexpected neighbor dump sequence")
			}
			if m.Header.Type == unix.NLMSG_DONE && m.Header.Seq == b.sequence {
				done = true
				continue
			}
			e, ok, err := parseEvent(m)
			if err != nil {
				return false, err
			}
			if !ok {
				continue
			}
			if m.Header.Seq == 0 {
				// An overlapping change makes the snapshot ambiguous. Drain the
				// dump, then retry rather than overwriting newer events with rows
				// from a partially enumerated table.
				changed = true
				continue
			}
			if err := t.apply(e); err != nil {
				return false, err
			}
		}
		if done {
			return changed, nil
		}
	}
}

func (b *linuxBackend) Snapshot(ctx context.Context) (*table, error) {
	linkRequest, _ := (&rtnetlink.LinkMessage{}).MarshalBinary()
	neighborRequest, _ := (&rtnetlink.NeighMessage{}).MarshalBinary()
	addressRequest, _ := (&rtnetlink.AddressMessage{}).MarshalBinary()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		t := newTable()
		linksChanged, err := b.dump(ctx, unix.RTM_GETLINK, linkRequest, t)
		if err != nil {
			return nil, fmt.Errorf("dump links: %w", err)
		}
		addressesChanged, err := b.dump(ctx, unix.RTM_GETADDR, addressRequest, t)
		if err != nil {
			return nil, fmt.Errorf("dump addresses: %w", err)
		}
		neighborsChanged, err := b.dump(ctx, unix.RTM_GETNEIGH, neighborRequest, t)
		if err != nil {
			return nil, fmt.Errorf("dump neighbors: %w", err)
		}
		if !linksChanged && !addressesChanged && !neighborsChanged {
			return t, nil
		}
	}
}

func (b *linuxBackend) Next(ctx context.Context) ([]event, error) {
	messages, err := b.receive(ctx)
	if err != nil {
		return nil, err
	}
	var events []event
	for _, m := range messages {
		e, ok, err := parseEvent(m)
		if err != nil {
			return nil, err
		}
		if ok {
			events = append(events, e)
		}
	}
	return events, nil
}

func parseEvent(m syscall.NetlinkMessage) (event, bool, error) {
	switch m.Header.Type {
	case unix.RTM_NEWLINK, unix.RTM_DELLINK:
		var link rtnetlink.LinkMessage
		if err := link.UnmarshalBinary(m.Data); err != nil {
			return event{}, false, err
		}
		e := event{index: int(link.Index), link: true, remove: m.Header.Type == unix.RTM_DELLINK}
		if link.Attributes != nil {
			e.name = link.Attributes.Name
			e.probeable = link.Type == unix.ARPHRD_ETHER && link.Flags&unix.IFF_UP != 0 && link.Flags&(unix.IFF_LOOPBACK|unix.IFF_POINTOPOINT|unix.IFF_NOARP) == 0 && (link.Attributes.Master == nil || *link.Attributes.Master == 0)
		}
		return e, e.index > 0 && (e.remove || e.name != ""), nil
	case unix.RTM_NEWADDR, unix.RTM_DELADDR:
		var a rtnetlink.AddressMessage
		if err := a.UnmarshalBinary(m.Data); err != nil {
			return event{}, false, err
		}
		if a.Index == 0 || a.Attributes == nil || (a.Family != unix.AF_INET && a.Family != unix.AF_INET6) {
			return event{}, false, nil
		}
		addr := a.Attributes.Local
		if len(addr) == 0 {
			addr = a.Attributes.Address
		}
		ip, ok := netip.AddrFromSlice(addr)
		if !ok || int(a.PrefixLength) > ip.BitLen() {
			return event{}, false, nil
		}
		flags := uint32(a.Flags) | a.Attributes.Flags
		return event{index: int(a.Index), address: true, prefix: netip.PrefixFrom(ip, int(a.PrefixLength)), remove: m.Header.Type == unix.RTM_DELADDR || flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) != 0}, true, nil
	case unix.RTM_NEWNEIGH, unix.RTM_DELNEIGH:
		var neigh rtnetlink.NeighMessage
		if err := neigh.UnmarshalBinary(m.Data); err != nil {
			return event{}, false, err
		}
		if (neigh.Family != unix.AF_INET && neigh.Family != unix.AF_INET6) || neigh.Index == 0 || neigh.Attributes == nil {
			return event{}, false, nil
		}
		ip, ok := netip.AddrFromSlice(neigh.Attributes.Address)
		if !ok || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
			return event{}, false, nil
		}
		e := event{index: int(neigh.Index), ip: ip.Unmap(), remove: m.Header.Type == unix.RTM_DELNEIGH}
		const valid = unix.NUD_REACHABLE | unix.NUD_STALE | unix.NUD_DELAY | unix.NUD_PROBE | unix.NUD_PERMANENT | unix.NUD_NOARP
		addr := neigh.Attributes.LLAddress
		if neigh.State&valid == 0 || neigh.State&(unix.NUD_INCOMPLETE|unix.NUD_FAILED) != 0 || neigh.Flags&unix.NTF_PROXY != 0 || len(addr) != 6 {
			e.remove = true
		} else {
			copy(e.mac[:], addr)
			if e.mac == (MAC{}) || e.mac[0]&1 != 0 {
				e.remove = true
			}
		}
		return e, true, nil
	default:
		return event{}, false, nil
	}
}

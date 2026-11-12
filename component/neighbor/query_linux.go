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
	"github.com/mdlayher/socket"
	"golang.org/x/sys/unix"
)

type linuxQuery struct{ linuxBackend }

func openQueryBackend() (queryBackend, error) {
	conn, err := socket.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE, "mihomo-neighbor-query", nil)
	if err != nil {
		return nil, err
	}
	if err = conn.Bind(&unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		conn.Close()
		return nil, err
	}
	return &linuxQuery{linuxBackend{conn: conn, buffer: make([]byte, 65536)}}, nil
}

func (q *linuxQuery) request(ctx context.Context, index int, ip netip.Addr, probe bool) (event, error) {
	if index <= 0 || !ip.IsValid() || ip.Zone() != "" {
		return event{}, errors.New("neighbor query requires an interface and an unscoped address")
	}
	family := uint16(unix.AF_INET6)
	if ip.Is4() {
		family = unix.AF_INET
	}
	req := &rtnetlink.NeighMessage{Family: family, Index: uint32(index)}
	kind := unix.RTM_GETNEIGH
	flags := netlink.Request
	if probe {
		kind = unix.RTM_NEWNEIGH
		flags |= netlink.Create | netlink.Excl | netlink.Acknowledge
		req.Flags = unix.NTF_USE
		// CREATE|EXCL is essential: NTF_USE without EXCL can remove the permanent
		// state from an administrator's existing entry. Existing entries are left
		// untouched; an INCOMPLETE entry already has kernel discovery in progress.
	}
	// The library's generic NeighAttributes encoder also emits NDA_UNSPEC,
	// NDA_LLADDR and NDA_IFINDEX, which strict RTM_GETNEIGH rejects. Encode
	// only NDA_DST; the interface belongs in the fixed ndmsg header.
	data, err := req.MarshalBinary()
	if err != nil {
		return event{}, err
	}
	ae := netlink.NewAttributeEncoder()
	ae.Bytes(unix.NDA_DST, ip.AsSlice())
	attrs, err := ae.Encode()
	if err != nil {
		return event{}, err
	}
	data = append(data, attrs...)
	q.sequence++
	msg := netlink.Message{Header: netlink.Header{Length: uint32(unix.NLMSG_HDRLEN + len(data)), Type: netlink.HeaderType(kind), Flags: flags, Sequence: q.sequence}, Data: data}
	wire, err := msg.MarshalBinary()
	if err != nil {
		return event{}, err
	}
	if err = q.conn.Sendto(ctx, wire, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return event{}, err
	}
	messages, err := q.receive(ctx)
	if err != nil {
		return event{}, err
	}
	for _, m := range messages {
		if m.Header.Seq != q.sequence {
			return event{}, errors.New("unexpected neighbor query sequence")
		}
		if probe && m.Header.Type == unix.NLMSG_ERROR {
			return event{}, nil
		} // validated zero-error ACK
		if !probe && m.Header.Type == unix.RTM_NEWNEIGH {
			e, ok, err := parseEvent(m)
			if err != nil {
				return event{}, err
			}
			if !ok || e.index != index || e.ip != ip {
				return event{}, errors.New("neighbor reply does not match query")
			}
			return e, nil
		}
	}
	return event{}, fmt.Errorf("missing neighbor query reply for %s", ip)
}

func (q *linuxQuery) Get(ctx context.Context, index int, ip netip.Addr) (MAC, bool, error) {
	e, err := q.request(ctx, index, ip, false)
	if errors.Is(err, syscall.ENOENT) {
		return MAC{}, false, nil
	}
	if err != nil {
		return MAC{}, false, err
	}
	return e.mac, !e.remove, nil
}
func (q *linuxQuery) Probe(ctx context.Context, index int, ip netip.Addr) error {
	_, err := q.request(ctx, index, ip, true)
	if errors.Is(err, syscall.EEXIST) {
		return nil
	}
	return err
}

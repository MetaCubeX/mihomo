package socks4

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/metacubex/mihomo/component/auth"
)

const Version = 0x04

type Command = uint8

const (
	CmdConnect Command = 0x01
	CmdBind    Command = 0x02
)

type Code = uint8

const (
	RequestGranted          Code = 90
	RequestRejected         Code = 91
	RequestIdentdFailed     Code = 92
	RequestIdentdMismatched Code = 93
)

var (
	errVersionMismatched   = errors.New("version code mismatched")
	errCommandNotSupported = errors.New("command not supported")
	errIPv6NotSupported    = errors.New("IPv6 not supported")

	ErrRequestRejected         = errors.New("request rejected or failed")
	ErrRequestIdentdFailed     = errors.New("request rejected because SOCKS server cannot connect to identd on the client")
	ErrRequestIdentdMismatched = errors.New("request rejected because the client program and identd report different user-ids")
	ErrRequestUnknownCode      = errors.New("request failed with unknown code")
)

var subnet = netip.PrefixFrom(netip.IPv4Unspecified(), 24)

func ServerHandshake(rw io.ReadWriter, authenticator auth.Authenticator) (addr string, command Command, err error) {
	var req [8]byte
	if _, err = io.ReadFull(rw, req[:]); err != nil {
		return
	}

	if req[0] != Version {
		err = errVersionMismatched
		return
	}

	if command = req[1]; command != CmdConnect {
		err = errCommandNotSupported
		return
	}

	var (
		dstIP   = netip.AddrFrom4(*(*[4]byte)(req[4:8])) // [4]byte
		dstPort = req[2:4]                               // [2]byte
	)

	var (
		host   string
		port   string
		code   uint8
		userID []byte
	)
	if userID, err = readUntilNull(rw); err != nil {
		return
	}

	if isReservedIP(dstIP) {
		var target []byte
		if target, err = readUntilNull(rw); err != nil {
			return
		}
		host = string(target)
	}

	port = strconv.Itoa(int(binary.BigEndian.Uint16(dstPort)))
	if host != "" {
		addr = net.JoinHostPort(host, port)
	} else {
		addr = net.JoinHostPort(dstIP.String(), port)
	}

	// SOCKS4 only support USERID auth.
	if authenticator == nil || authenticator.Verify(string(userID), "") {
		code = RequestGranted
	} else {
		code = RequestIdentdMismatched
		err = ErrRequestIdentdMismatched
	}

	var reply [8]byte
	reply[0] = 0x00 // reply code
	reply[1] = code // result code
	copy(reply[4:8], dstIP.AsSlice())
	copy(reply[2:4], dstPort)

	_, wErr := rw.Write(reply[:])
	if err == nil {
		err = wErr
	}
	return
}

func ClientHandshake(rw io.ReadWriter, addr string, command Command, userID string) (err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return err
	}

	dstIP, err := netip.ParseAddr(host)
	if err != nil /* HOST */ {
		dstIP = netip.AddrFrom4([4]byte{0, 0, 0, 1})
	} else if dstIP.Is6() /* IPv6 */ {
		return errIPv6NotSupported
	}

	req := &bytes.Buffer{}
	req.WriteByte(Version)
	req.WriteByte(command)
	_ = binary.Write(req, binary.BigEndian, uint16(port))
	req.Write(dstIP.AsSlice())
	req.WriteString(userID)
	req.WriteByte(0) /* NULL */

	if isReservedIP(dstIP) /* SOCKS4A */ {
		req.WriteString(host)
		req.WriteByte(0) /* NULL */
	}

	if _, err = rw.Write(req.Bytes()); err != nil {
		return err
	}

	var resp [8]byte
	if _, err = io.ReadFull(rw, resp[:]); err != nil {
		return err
	}

	if resp[0] != 0x00 {
		return errVersionMismatched
	}

	switch resp[1] {
	case RequestGranted:
		return nil
	case RequestRejected:
		return ErrRequestRejected
	case RequestIdentdFailed:
		return ErrRequestIdentdFailed
	case RequestIdentdMismatched:
		return ErrRequestIdentdMismatched
	default:
		return ErrRequestUnknownCode
	}
}

// For version 4A, if the client cannot resolve the destination host's
// domain name to find its IP address, it should set the first three bytes
// of DSTIP to NULL and the last byte to a non-zero value. (This corresponds
// to IP address 0.0.0.x, with x nonzero. As decreed by IANA  -- The
// Internet Assigned Numbers Authority -- such an address is inadmissible
// as a destination IP address and thus should never occur if the client
// can resolve the domain name.)
func isReservedIP(ip netip.Addr) bool {
	return !ip.IsUnspecified() && subnet.Contains(ip)
}

func readUntilNull(r io.Reader) ([]byte, error) {
	buf := &bytes.Buffer{}
	var data [1]byte

	for {
		if _, err := r.Read(data[:]); err != nil {
			return nil, err
		}
		if data[0] == 0 {
			return buf.Bytes(), nil
		}
		buf.WriteByte(data[0])
	}
}

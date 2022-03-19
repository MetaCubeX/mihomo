package process

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"syscall"
	"unicode"
	"unsafe"

	"github.com/Dreamacro/clash/common/pool"
)

// from https://github.com/vishvananda/netlink/blob/bca67dfc8220b44ef582c9da4e9172bf1c9ec973/nl/nl_linux.go#L52-L62
var nativeEndian = func() binary.ByteOrder {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		return binary.BigEndian
	}

	return binary.LittleEndian
}()

const (
	sizeOfSocketDiagRequest = syscall.SizeofNlMsghdr + 8 + 48
	socketDiagByFamily      = 20
	pathProc                = "/proc"
)

func findProcessName(network string, ip net.IP, srcPort int) (string, error) {
	inode, uid, err := resolveSocketByNetlink(network, ip, srcPort)
	if err != nil {
		return "", err
	}

	return resolveProcessNameByProcSearch(inode, uid)
}

func resolveSocketByNetlink(network string, ip net.IP, srcPort int) (int32, int32, error) {
	var family byte
	var protocol byte

	switch network {
	case TCP:
		protocol = syscall.IPPROTO_TCP
	case UDP:
		protocol = syscall.IPPROTO_UDP
	default:
		return 0, 0, ErrInvalidNetwork
	}

	if ip.To4() != nil {
		family = syscall.AF_INET
	} else {
		family = syscall.AF_INET6
	}

	req := packSocketDiagRequest(family, protocol, ip, uint16(srcPort))

	socket, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_INET_DIAG)
	if err != nil {
		return 0, 0, fmt.Errorf("dial netlink: %w", err)
	}
	defer syscall.Close(socket)

	syscall.SetsockoptTimeval(socket, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &syscall.Timeval{Usec: 100})
	syscall.SetsockoptTimeval(socket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 100})

	if err := syscall.Connect(socket, &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pad:    0,
		Pid:    0,
		Groups: 0,
	}); err != nil {
		return 0, 0, err
	}

	if _, err := syscall.Write(socket, req); err != nil {
		return 0, 0, fmt.Errorf("write request: %w", err)
	}

	rb := pool.Get(pool.RelayBufferSize)
	defer pool.Put(rb)

	n, err := syscall.Read(socket, rb)
	if err != nil {
		return 0, 0, fmt.Errorf("read response: %w", err)
	}

	messages, err := syscall.ParseNetlinkMessage(rb[:n])
	if err != nil {
		return 0, 0, fmt.Errorf("parse netlink message: %w", err)
	} else if len(messages) == 0 {
		return 0, 0, fmt.Errorf("unexcepted netlink response")
	}

	message := messages[0]
	if message.Header.Type&syscall.NLMSG_ERROR != 0 {
		return 0, 0, fmt.Errorf("netlink message: NLMSG_ERROR")
	}

	inode, uid := unpackSocketDiagResponse(&messages[0])
	if inode < 0 || uid < 0 {
		return 0, 0, fmt.Errorf("invalid inode(%d) or uid(%d)", inode, uid)
	}

	return inode, uid, nil
}

func packSocketDiagRequest(family, protocol byte, source net.IP, sourcePort uint16) []byte {
	s := make([]byte, 16)

	if v4 := source.To4(); v4 != nil {
		copy(s, v4)
	} else {
		copy(s, source)
	}

	buf := make([]byte, sizeOfSocketDiagRequest)

	nativeEndian.PutUint32(buf[0:4], sizeOfSocketDiagRequest)
	nativeEndian.PutUint16(buf[4:6], socketDiagByFamily)
	nativeEndian.PutUint16(buf[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	nativeEndian.PutUint32(buf[8:12], 0)
	nativeEndian.PutUint32(buf[12:16], 0)

	buf[16] = family
	buf[17] = protocol
	buf[18] = 0
	buf[19] = 0
	nativeEndian.PutUint32(buf[20:24], 0xFFFFFFFF)

	binary.BigEndian.PutUint16(buf[24:26], sourcePort)
	binary.BigEndian.PutUint16(buf[26:28], 0)

	copy(buf[28:44], s)
	copy(buf[44:60], net.IPv6zero)

	nativeEndian.PutUint32(buf[60:64], 0)
	nativeEndian.PutUint64(buf[64:72], 0xFFFFFFFFFFFFFFFF)

	return buf
}

func unpackSocketDiagResponse(msg *syscall.NetlinkMessage) (inode, uid int32) {
	if len(msg.Data) < 72 {
		return 0, 0
	}

	data := msg.Data

	uid = int32(nativeEndian.Uint32(data[64:68]))
	inode = int32(nativeEndian.Uint32(data[68:72]))

	return
}

func resolveProcessNameByProcSearch(inode, uid int32) (string, error) {
	files, err := os.ReadDir(pathProc)
	if err != nil {
		return "", err
	}

	buffer := make([]byte, syscall.PathMax)
	socket := []byte(fmt.Sprintf("socket:[%d]", inode))

	for _, f := range files {
		if !f.IsDir() || !isPid(f.Name()) {
			continue
		}

		info, err := f.Info()
		if err != nil {
			return "", err
		}
		if info.Sys().(*syscall.Stat_t).Uid != uint32(uid) {
			continue
		}

		processPath := path.Join(pathProc, f.Name())
		fdPath := path.Join(processPath, "fd")

		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			n, err := syscall.Readlink(path.Join(fdPath, fd.Name()), buffer)
			if err != nil {
				continue
			}

			if bytes.Equal(buffer[:n], socket) {
				return os.Readlink(path.Join(processPath, "exe"))
			}
		}
	}

	return "", fmt.Errorf("process of uid(%d),inode(%d) not found", uid, inode)
}

func isPid(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return !unicode.IsDigit(r)
	}) == -1
}

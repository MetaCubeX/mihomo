package process

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unicode"
	"unsafe"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	SOCK_DIAG_BY_FAMILY  = 20
	inetDiagRequestSize  = int(unsafe.Sizeof(inetDiagRequest{}))
	inetDiagResponseSize = int(unsafe.Sizeof(inetDiagResponse{}))
)

type inetDiagRequest struct {
	Family   byte
	Protocol byte
	Ext      byte
	Pad      byte
	States   uint32

	SrcPort [2]byte
	DstPort [2]byte
	Src     [16]byte
	Dst     [16]byte
	If      uint32
	Cookie  [2]uint32
}

type inetDiagResponse struct {
	Family  byte
	State   byte
	Timer   byte
	ReTrans byte

	SrcPort [2]byte
	DstPort [2]byte
	Src     [16]byte
	Dst     [16]byte
	If      uint32
	Cookie  [2]uint32

	Expires uint32
	RQueue  uint32
	WQueue  uint32
	UID     uint32
	INode   uint32
}

func findProcessName(network string, ip netip.Addr, srcPort int) (uint32, string, error) {
	uid, inode, err := resolveSocketByNetlink(network, ip, srcPort)
	if err != nil {
		return 0, "", err
	}
	pp, err := resolveProcessNameByProcSearch(inode, uid)
	return uid, pp, err
}

func resolveSocketByNetlink(network string, ip netip.Addr, srcPort int) (uint32, uint32, error) {
	request := &inetDiagRequest{
		States: 0xffffffff,
		Cookie: [2]uint32{0xffffffff, 0xffffffff},
	}

	if ip.Is4() {
		request.Family = unix.AF_INET
	} else {
		request.Family = unix.AF_INET6
	}

	if strings.HasPrefix(network, "tcp") {
		request.Protocol = unix.IPPROTO_TCP
	} else if strings.HasPrefix(network, "udp") {
		request.Protocol = unix.IPPROTO_UDP
	} else {
		return 0, 0, ErrInvalidNetwork
	}

	copy(request.Src[:], ip.AsSlice())

	binary.BigEndian.PutUint16(request.SrcPort[:], uint16(srcPort))

	conn, err := netlink.Dial(unix.NETLINK_INET_DIAG, nil)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()

	message := netlink.Message{
		Header: netlink.Header{
			Type:  SOCK_DIAG_BY_FAMILY,
			Flags: netlink.Request | netlink.Dump,
		},
		Data: (*(*[inetDiagRequestSize]byte)(unsafe.Pointer(request)))[:],
	}

	messages, err := conn.Execute(message)
	if err != nil {
		return 0, 0, err
	}

	for _, msg := range messages {
		if len(msg.Data) < inetDiagResponseSize {
			continue
		}

		response := (*inetDiagResponse)(unsafe.Pointer(&msg.Data[0]))

		return response.UID, response.INode, nil
	}

	return 0, 0, ErrNotFound
}

func resolveProcessNameByProcSearch(inode, uid uint32) (string, error) {
	files, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}

	buffer := make([]byte, unix.PathMax)
	socket := fmt.Appendf(nil, "socket:[%d]", inode)

	for _, f := range files {
		if !f.IsDir() || !isPid(f.Name()) {
			continue
		}

		info, err := f.Info()
		if err != nil {
			return "", err
		}
		if info.Sys().(*syscall.Stat_t).Uid != uid {
			continue
		}

		processPath := filepath.Join("/proc", f.Name())
		fdPath := filepath.Join(processPath, "fd")

		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			n, err := unix.Readlink(filepath.Join(fdPath, fd.Name()), buffer)
			if err != nil {
				continue
			}

			if runtime.GOOS == "android" {
				if bytes.Equal(buffer[:n], socket) {
					cmdline, err := os.ReadFile(path.Join(processPath, "cmdline"))
					if err != nil {
						return "", err
					}

					return splitCmdline(cmdline), nil
				}
			} else {
				if bytes.Equal(buffer[:n], socket) {
					return os.Readlink(filepath.Join(processPath, "exe"))
				}
			}
		}
	}

	return "", fmt.Errorf("process of uid(%d),inode(%d) not found", uid, inode)
}

func splitCmdline(cmdline []byte) string {
	cmdline = bytes.Trim(cmdline, " ")

	idx := bytes.IndexFunc(cmdline, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	})

	if idx == -1 {
		return filepath.Base(string(cmdline))
	}
	return filepath.Base(string(cmdline[:idx]))
}

func isPid(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return !unicode.IsDigit(r)
	}) == -1
}

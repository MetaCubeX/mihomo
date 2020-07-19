package rules

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

type Process struct {
	adapter string
	process string
}

func (ps *Process) RuleType() C.RuleType {
	return C.Process
}

func (ps *Process) Match(metadata *C.Metadata) bool {
	name, err := getExecPathFromAddress(metadata.SrcIP, metadata.SrcPort, metadata.NetWork == C.TCP)
	if err != nil {
		log.Debugln("[%s] getExecPathFromAddress error: %s", C.Process.String(), err.Error())
		return false
	}

	return strings.ToLower(name) == ps.process
}

func (p *Process) Adapter() string {
	return p.adapter
}

func (p *Process) Payload() string {
	return p.process
}

func (p *Process) NoResolveIP() bool {
	return true
}

func NewProcess(process string, adapter string) (*Process, error) {
	return &Process{
		adapter: adapter,
		process: process,
	}, nil
}

const (
	procpidpathinfo     = 0xb
	procpidpathinfosize = 1024
	proccallnumpidinfo  = 0x2
)

func getExecPathFromPID(pid uint32) (string, error) {
	buf := make([]byte, procpidpathinfosize)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PROC_INFO,
		proccallnumpidinfo,
		uintptr(pid),
		procpidpathinfo,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		procpidpathinfosize)
	if errno != 0 {
		return "", errno
	}
	firstZero := bytes.IndexByte(buf, 0)
	if firstZero <= 0 {
		return "", nil
	}

	return filepath.Base(string(buf[:firstZero])), nil
}

func getExecPathFromAddress(ip net.IP, portStr string, isTCP bool) (string, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", err
	}

	spath := "net.inet.tcp.pcblist_n"
	if !isTCP {
		spath = "net.inet.udp.pcblist_n"
	}

	value, err := syscall.Sysctl(spath)
	if err != nil {
		return "", err
	}

	buf := []byte(value)

	var kinds uint32 = 0
	so, inp := 0, 0
	for i := roundUp8(xinpgenSize(buf)); i < uint32(len(buf)) && xinpgenSize(buf[i:]) > 24; i += roundUp8(xinpgenSize(buf[i:])) {
		thisKind := binary.LittleEndian.Uint32(buf[i+4 : i+8])
		if kinds&thisKind == 0 {
			kinds |= thisKind
			switch thisKind {
			case 0x1:
				// XSO_SOCKET
				so = int(i)
			case 0x10:
				// XSO_INPCB
				inp = int(i)
			default:
				break
			}
		}

		// all blocks needed by tcp/udp
		if (isTCP && kinds != 0x3f) || (!isTCP && kinds != 0x1f) {
			continue
		}
		kinds = 0

		// xsocket_n.xso_protocol
		proto := binary.LittleEndian.Uint32(buf[so+36 : so+40])
		if proto != syscall.IPPROTO_TCP && proto != syscall.IPPROTO_UDP {
			continue
		}

		srcPort := binary.BigEndian.Uint16(buf[inp+18 : inp+20])
		if uint16(port) != srcPort {
			continue
		}

		// xinpcb_n.inp_vflag
		flag := buf[inp+44]

		var srcIP net.IP
		if flag&0x1 > 0 {
			// ipv4
			srcIP = net.IP(buf[inp+76 : inp+80])
		} else if flag&0x2 > 0 {
			// ipv6
			srcIP = net.IP(buf[inp+64 : inp+80])
		} else {
			continue
		}

		if !ip.Equal(srcIP) {
			continue
		}

		// xsocket_n.so_last_pid
		pid := binary.LittleEndian.Uint32(buf[so+68 : so+72])
		return getExecPathFromPID(pid)
	}

	return "", errors.New("process not found")
}

func xinpgenSize(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b[:4])
}

func roundUp8(n uint32) uint32 {
	if n == 0 {
		return uint32(8)
	}
	return (n + 7) & ((^uint32(8)) + 1)
}

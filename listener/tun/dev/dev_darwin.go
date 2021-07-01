// +build darwin

package dev

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/Dreamacro/clash/common/pool"
)

const utunControlName = "com.apple.net.utun_control"
const _IOC_OUT = 0x40000000
const _IOC_IN = 0x80000000
const _IOC_INOUT = _IOC_IN | _IOC_OUT

// _CTLIOCGINFO value derived from /usr/include/sys/{kern_control,ioccom}.h
// https://github.com/apple/darwin-xnu/blob/master/bsd/sys/ioccom.h

// #define CTLIOCGINFO     _IOWR('N', 3, struct ctl_info)	/* get id from name */ = 0xc0644e03
const _CTLIOCGINFO = _IOC_INOUT | ((100 & 0x1fff) << 16) | uint32(byte('N'))<<8 | 3

// #define	SIOCAIFADDR_IN6		_IOW('i', 26, struct in6_aliasreq) = 0x8080691a
//const _SIOCAIFADDR_IN6 = _IOC_IN | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 26

// #define	SIOCPROTOATTACH_IN6	_IOWR('i', 110, struct in6_aliasreq_64)
const _SIOCPROTOATTACH_IN6 = _IOC_INOUT | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 110

// #define	SIOCLL_START		_IOWR('i', 130, struct in6_aliasreq)
const _SIOCLL_START = _IOC_INOUT | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 130

// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/nd6.h#L469
const ND6_INFINITE_LIFETIME = 0xffffffff

// Following the wireguard-go solution:
// These unix.SYS_* constants were removed from golang.org/x/sys/unix
// so copy them here for now.
// See https://github.com/golang/go/issues/41868
const (
	sys_IOCTL      = 54
	sys_CONNECT    = 98
	sys_GETSOCKOPT = 118
)

type tunDarwin struct {
	//url       string
	name       string
	tunAddress string
	autoRoute  bool
	tunFile    *os.File
	errors     chan error

	closed   bool
	stopOnce sync.Once
}

// sockaddr_ctl specifeid in /usr/include/sys/kern_control.h
type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scID       uint32
	scUnit     uint32
	scReserved [5]uint32
}

// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/net/if.h#L402-L563

//type ifreqAddr struct {
//	Name [unix.IFNAMSIZ]byte
//	Addr unix.RawSockaddrInet4
//	Pad  [8]byte
//}

var sockaddrCtlSize uintptr = 32

// OpenTunDevice return a TunDevice according a URL
func OpenTunDevice(tunAddress string, autoRoute bool) (TunDevice, error) {

	name := "utun"
	// TODO: configure the MTU
	mtu := 9000

	ifIndex := -1
	if name != "utun" {
		_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
		if err != nil || ifIndex < 0 {
			return nil, fmt.Errorf("interface name must be utun[0-9]*")
		}
	}

	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)

	if err != nil {
		return nil, err
	}

	var ctlInfo = &struct {
		ctlID   uint32
		ctlName [96]byte
	}{}

	copy(ctlInfo.ctlName[:], []byte(utunControlName))

	_, _, errno := unix.Syscall(
		sys_IOCTL,
		uintptr(fd),
		uintptr(_CTLIOCGINFO),
		uintptr(unsafe.Pointer(ctlInfo)),
	)

	if errno != 0 {
		return nil, fmt.Errorf("_CTLIOCGINFO: %v", errno)
	}

	sc := sockaddrCtl{
		scLen:     uint8(sockaddrCtlSize),
		scFamily:  unix.AF_SYSTEM,
		ssSysaddr: 2,
		scID:      ctlInfo.ctlID,
		scUnit:    uint32(ifIndex) + 1,
	}

	scPointer := unsafe.Pointer(&sc)

	_, _, errno = unix.RawSyscall(
		sys_CONNECT,
		uintptr(fd),
		uintptr(scPointer),
		uintptr(sockaddrCtlSize),
	)

	if errno != 0 {
		return nil, fmt.Errorf("SYS_CONNECT: %v", errno)
	}

	err = syscall.SetNonblock(fd, true)
	if err != nil {
		return nil, err
	}

	tun, err := CreateTUNFromFile(os.NewFile(uintptr(fd), ""), mtu, tunAddress, autoRoute)

	if err != nil {
		return nil, err
	}

	if autoRoute {
		SetLinuxAutoRoute()
	}

	return tun, nil
}

func CreateTUNFromFile(file *os.File, mtu int, tunAddress string, autoRoute bool) (TunDevice, error) {
	tun := &tunDarwin{
		tunFile:    file,
		tunAddress: tunAddress,
		autoRoute:  autoRoute,
		errors:     make(chan error, 5),
	}

	name, err := tun.getName()
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}
	tun.name = name

	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	if mtu > 0 {
		err = tun.setMTU(mtu)
		if err != nil {
			tun.Close()
			return nil, err
		}
	}

	// This address doesn't mean anything here. NIC just net an IP address to set route upon.
	// TODO: maybe let user config it. And I'm doubt whether we really need it.
	p2pAddress := net.ParseIP("198.18.0.1")
	err = tun.setTunAddress(p2pAddress)
	if err != nil {
		tun.Close()
		return nil, err
	}
	err = tun.attachLinkLocal()
	if err != nil {
		tun.Close()
		return nil, err
	}

	return tun, nil
}

func (t *tunDarwin) Name() string {
	return t.name
}

func (t *tunDarwin) URL() string {
	return fmt.Sprintf("dev://%s", t.Name())
}

func (t *tunDarwin) MTU() (int, error) {
	return t.getInterfaceMtu()
}

func (t *tunDarwin) Read(buff []byte) (int, error) {
	select {
	case err := <-t.errors:
		return 0, err
	default:
		n, err := t.tunFile.Read(buff)
		if n < 4 {
			return 0, err
		}

		copy(buff[:], buff[4:])
		return n - 4, err
	}
}

func (t *tunDarwin) Write(buff []byte) (int, error) {
	// reserve space for header
	buf := pool.Get(pool.RelayBufferSize)
	defer pool.Put(buf[:cap(buf)])

	buf[0] = 0x00
	buf[1] = 0x00
	buf[2] = 0x00

	copy(buf[4:], buff)
	if buf[4]>>4 == ipv6.Version {
		buf[3] = unix.AF_INET6
	} else {
		buf[3] = unix.AF_INET
	}

	// write
	return t.tunFile.Write(buf[:4+len(buff)])
}

func (t *tunDarwin) IsClose() bool {
	return t.closed
}

func (t *tunDarwin) Close() error {
	t.stopOnce.Do(func() {
		if t.autoRoute {
			RemoveLinuxAutoRoute()
		}
		t.closed = true
		t.tunFile.Close()
	})
	return nil
}

func (t *tunDarwin) getInterfaceMtu() (int, error) {

	// open datagram socket

	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)

	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	// do ioctl call

	var ifr [64]byte
	copy(ifr[:], t.name)
	_, _, errno := unix.Syscall(
		sys_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return 0, fmt.Errorf("failed to get MTU on %s", t.name)
	}

	return int(*(*int32)(unsafe.Pointer(&ifr[16]))), nil
}

func (t *tunDarwin) getName() (string, error) {
	var ifName struct {
		name [16]byte
	}
	ifNameSize := uintptr(16)

	var errno syscall.Errno
	t.operateOnFd(func(fd uintptr) {
		_, _, errno = unix.Syscall6(
			sys_GETSOCKOPT,
			fd,
			2, /* #define SYSPROTO_CONTROL 2 */
			2, /* #define UTUN_OPT_IFNAME 2 */
			uintptr(unsafe.Pointer(&ifName)),
			uintptr(unsafe.Pointer(&ifNameSize)), 0)
	})

	if errno != 0 {
		return "", fmt.Errorf("SYS_GETSOCKOPT: %v", errno)
	}

	t.name = string(ifName.name[:ifNameSize-1])
	return t.name, nil
}

func (t *tunDarwin) setMTU(n int) error {
	// open datagram socket
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)

	if err != nil {
		return err
	}

	defer unix.Close(fd)

	// do ioctl call

	var ifr [32]byte
	copy(ifr[:], t.name)
	*(*uint32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = uint32(n)
	_, _, errno := unix.Syscall(
		sys_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return fmt.Errorf("failed to set MTU on %s", t.name)
	}

	return nil
}

func (t *tunDarwin) operateOnFd(fn func(fd uintptr)) {
	sysconn, err := t.tunFile.SyscallConn()
	// TODO: consume the errors
	if err != nil {
		t.errors <- fmt.Errorf("unable to find sysconn for tunfile: %s", err.Error())
		return
	}
	err = sysconn.Control(fn)
	if err != nil {
		t.errors <- fmt.Errorf("unable to control sysconn for tunfile: %s", err.Error())
	}
}

func (t *tunDarwin) setTunAddress(addr net.IP) error {
	var ifr [unix.IFNAMSIZ]byte
	copy(ifr[:], t.name)

	// set IPv4 address
	fd4, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return err
	}
	defer syscall.Close(fd4)

	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/sys/sockio.h#L107
	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/net/if.h#L570-L575
	// https://man.openbsd.org/netintro.4#SIOCAIFADDR
	type aliasreq struct {
		ifra_name    [unix.IFNAMSIZ]byte
		ifra_addr    unix.RawSockaddrInet4
		ifra_dstaddr unix.RawSockaddrInet4
		ifra_mask    unix.RawSockaddrInet4
	}

	var ip4 [4]byte
	copy(ip4[:], addr.To4())
	ip4mask := [4]byte{255, 255, 0, 0}
	ifra4 := aliasreq{
		ifra_name: ifr,
		ifra_addr: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   ip4,
		},
		ifra_dstaddr: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   ip4,
		},
		ifra_mask: unix.RawSockaddrInet4{
			Len:    unix.SizeofSockaddrInet4,
			Family: unix.AF_INET,
			Addr:   ip4mask,
		},
	}

	if _, _, errno := unix.Syscall(
		sys_IOCTL,
		uintptr(fd4),
		uintptr(unix.SIOCAIFADDR),
		uintptr(unsafe.Pointer(&ifra4)),
	); errno != 0 {
		return fmt.Errorf("failed to set ip address on %s: %v", t.name, errno)
	}

	return nil
}

func (t *tunDarwin) attachLinkLocal() error {
	var ifr [unix.IFNAMSIZ]byte
	copy(ifr[:], t.name)

	// attach link-local address
	fd6, err := unix.Socket(
		unix.AF_INET6,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return err
	}
	defer syscall.Close(fd6)
	// SIOCAIFADDR_IN6
	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6_var.h#L114-L119
	// https://opensource.apple.com/source/network_cmds/network_cmds-543.260.3/
	type in6_addrlifetime struct {
		//ia6t_expire    uint64
		//ia6t_preferred uint64
		//ia6t_vltime    uint32
		//ia6t_pltime    uint32
	}
	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6_var.h#L336-L343
	// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6.h#L174-L181
	type in6_aliasreq struct {
		ifra_name       [unix.IFNAMSIZ]byte
		ifra_addr       unix.RawSockaddrInet6
		ifra_dstaddr    unix.RawSockaddrInet6
		ifra_prefixmask unix.RawSockaddrInet6
		ifra_flags      int32
		ifra_lifetime   in6_addrlifetime
	}
	// Attach link-local address
	ifra6 := in6_aliasreq{
		ifra_name: ifr,
	}
	if _, _, errno := unix.Syscall(
		sys_IOCTL,
		uintptr(fd6),
		uintptr(_SIOCPROTOATTACH_IN6),
		uintptr(unsafe.Pointer(&ifra6)),
	); errno != 0 {
		return fmt.Errorf("failed to attach link-local address on %s: SIOCPROTOATTACH_IN6 %v", t.name, errno)
	}

	if _, _, errno := unix.Syscall(
		sys_IOCTL,
		uintptr(fd6),
		uintptr(_SIOCLL_START),
		uintptr(unsafe.Pointer(&ifra6)),
	); errno != 0 {
		return fmt.Errorf("failed to set ipv6 address on %s: SIOCLL_START %v", t.name, errno)
	}

	return nil
}

// GetAutoDetectInterface get ethernet interface
func GetAutoDetectInterface() (string, error) {
	cmd := exec.Command("bash", "-c", "netstat -rnf inet | grep 'default' | awk -F ' ' 'NR==1{print $6}' | xargs echo -n")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	if out.Len() == 0 {
		return "", errors.New("interface not found by default route")
	}
	return out.String(), nil
}

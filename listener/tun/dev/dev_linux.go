//go:build linux || android
// +build linux android

package dev

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/Dreamacro/clash/log"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	cloneDevicePath = "/dev/net/tun"
	ifReqSize       = unix.IFNAMSIZ + 64
)

type tunLinux struct {
	url        string
	name       string
	tunAddress string
	autoRoute  bool
	tunFile    *os.File
	mtu        int

	closed   bool
	stopOnce sync.Once
}

// OpenTunDevice return a TunDevice according a URL
func OpenTunDevice(tunAddress string, autoRoute bool) (TunDevice, error) {
	deviceURL, _ := url.Parse("dev://utun")
	mtu, _ := strconv.ParseInt(deviceURL.Query().Get("mtu"), 0, 32)

	t := &tunLinux{
		url:        deviceURL.String(),
		mtu:        int(mtu),
		tunAddress: tunAddress,
		autoRoute:  autoRoute,
	}
	switch deviceURL.Scheme {
	case "dev":
		var err error
		var dev TunDevice
		dev, err = t.openDeviceByName(deviceURL.Host)
		if err != nil {
			return nil, err
		}

		err = t.configInterface()
		if err != nil {
			return nil, err
		}

		if autoRoute {
			addRoute(tunAddress)
		}

		return dev, nil
	case "fd":
		fd, err := strconv.ParseInt(deviceURL.Host, 10, 32)
		if err != nil {
			return nil, err
		}
		var dev TunDevice
		dev, err = t.openDeviceByFd(int(fd))
		if err != nil {
			return nil, err
		}
		if autoRoute {
			log.Warnln("linux unsupported automatic route")
		}
		return dev, nil
	}
	return nil, fmt.Errorf("unsupported device type `%s`", deviceURL.Scheme)
}

func (t *tunLinux) Name() string {
	return t.name
}

func (t *tunLinux) URL() string {
	return t.url
}

func (t *tunLinux) Write(buff []byte) (int, error) {
	return t.tunFile.Write(buff)
}

func (t *tunLinux) Read(buff []byte) (int, error) {
	return t.tunFile.Read(buff)
}

func (t *tunLinux) IsClose() bool {
	return t.closed
}

func (t *tunLinux) Close() error {
	t.stopOnce.Do(func() {
		t.closed = true
		t.tunFile.Close()
	})
	return nil
}

func (t *tunLinux) MTU() (int, error) {
	// Sometime, we can't read MTU by SIOCGIFMTU. Then we should return the preset MTU
	if t.mtu > 0 {
		return t.mtu, nil
	}
	mtu, err := t.getInterfaceMtu()
	return int(mtu), err
}

func (t *tunLinux) openDeviceByName(name string) (TunDevice, error) {
	nfd, err := unix.Open(cloneDevicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var ifr [ifReqSize]byte
	var flags uint16 = unix.IFF_TUN | unix.IFF_NO_PI
	nameBytes := []byte(name)
	if len(nameBytes) >= unix.IFNAMSIZ {
		return nil, errors.New("interface name too long")
	}

	copy(ifr[:], nameBytes)

	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(nfd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return nil, errno
	}

	err = unix.SetNonblock(nfd, true)
	if err != nil {
		return nil, err
	}
	// Note that the above -- open,ioctl,nonblock -- must happen prior to handing it to netpoll as below this line.

	t.tunFile = os.NewFile(uintptr(nfd), cloneDevicePath)
	t.name, err = t.getName()
	if err != nil {
		t.tunFile.Close()
		return nil, err
	}

	return t, nil
}

func (t *tunLinux) configInterface() error {
	var ifr [ifReqSize]byte
	nameBytes := []byte(t.name)
	if len(nameBytes) >= unix.IFNAMSIZ {
		return errors.New("interface name too long")
	}

	copy(ifr[:], nameBytes)

	fd, _, errno := syscall.Syscall(unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, 0)
	if errno != 0 {
		return errno
	}

	// set addr for tun
	var ip []byte
	for _, num := range strings.Split(t.tunAddress, ".") {
		value, err := strconv.Atoi(num)
		if err != nil {
			return err
		}
		ip = append(ip, byte(value))
	}

	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = uint16(unix.AF_INET)

	copy(ifr[unix.IFNAMSIZ+4:], ip)

	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		fd,
		uintptr(unix.SIOCSIFADDR),
		uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return errno
	}

	// set netmask for tun
	netmask := []byte{255, 255, 0, 0}
	copy(ifr[unix.IFNAMSIZ+4:], netmask)

	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		fd,
		uintptr(unix.SIOCSIFNETMASK),
		uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return errno
	}

	// interface up
	_, _, errno = syscall.Syscall(unix.SYS_IOCTL, fd, uintptr(unix.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr[0])))

	var flags = uint16(unix.IFF_UP | unix.IFF_TUN | unix.IFF_MULTICAST | unix.IFF_RUNNING | unix.IFF_NOARP)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags

	_, _, errno = syscall.Syscall(
		unix.SYS_IOCTL,
		fd,
		uintptr(unix.SIOCSIFFLAGS),
		uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return errno
	}

	return nil
}

func (t *tunLinux) openDeviceByFd(fd int) (TunDevice, error) {
	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}

	fd, err := syscall.Dup(fd)
	if err != nil {
		return nil, err
	}

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TUNGETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return nil, errno
	}

	if ifr.flags&syscall.IFF_TUN == 0 || ifr.flags&syscall.IFF_NO_PI == 0 {
		return nil, errors.New("only tun device and no pi mode supported")
	}

	nullStr := ifr.name[:]
	i := bytes.IndexByte(nullStr, 0)
	if i != -1 {
		nullStr = nullStr[:i]
	}
	t.name = string(nullStr)
	t.tunFile = os.NewFile(uintptr(fd), "/dev/tun")

	return t, nil
}

func (t *tunLinux) getInterfaceMtu() (uint32, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}

	defer syscall.Close(fd)

	var ifreq struct {
		name [16]byte
		mtu  int32
		_    [20]byte
	}

	copy(ifreq.name[:], t.name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFMTU, uintptr(unsafe.Pointer(&ifreq)))
	if errno != 0 {
		return 0, errno
	}

	return uint32(ifreq.mtu), nil
}

func (t *tunLinux) getName() (string, error) {
	sysconn, err := t.tunFile.SyscallConn()
	if err != nil {
		return "", err
	}
	var ifr [ifReqSize]byte
	var errno syscall.Errno
	err = sysconn.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			fd,
			uintptr(unix.TUNGETIFF),
			uintptr(unsafe.Pointer(&ifr[0])),
		)
	})
	if err != nil {
		return "", errors.New("failed to get name of TUN device: " + err.Error())
	}
	if errno != 0 {
		return "", errors.New("failed to get name of TUN device: " + errno.Error())
	}
	nullStr := ifr[:]
	i := bytes.IndexByte(nullStr, 0)
	if i != -1 {
		nullStr = nullStr[:i]
	}
	t.name = string(nullStr)
	return t.name, nil
}

// GetAutoDetectInterface get ethernet interface
func GetAutoDetectInterface() (string, error) {
	cmd := exec.Command("bash", "-c", "ip route show | grep 'default via' | awk -F ' ' 'NR==1{print $5}' | xargs echo -n")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

func addRoute(gateway string) {
	cmd := exec.Command("route", "add", "default", "gw", gateway)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Errorln("[auto route] Failed to add system route: %s: %s , cmd: %s", err.Error(), stderr.String(), cmd.String())
	}
}

func delRoute(gateway string) {
	cmd := exec.Command("ip", "route", "delete", "gw")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Errorln("[auto route] Failed to delete system route: %s: %s , cmd: %s", err.Error(), stderr.String(), cmd.String())
	}
}

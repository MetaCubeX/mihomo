package wintun

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Session struct {
	handle uintptr
}

const (
	PacketSizeMax   = 0xffff    // Maximum packet size
	RingCapacityMin = 0x20000   // Minimum ring capacity (128 kiB)
	RingCapacityMax = 0x4000000 // Maximum ring capacity (64 MiB)
)

// Packet with data
type Packet struct {
	Next *Packet              // Pointer to next packet in queue
	Size uint32               // Size of packet (max WINTUN_MAX_IP_PACKET_SIZE)
	Data *[PacketSizeMax]byte // Pointer to layer 3 IPv4 or IPv6 packet
}

var (
	procWintunAllocateSendPacket   = modwintun.NewProc("WintunAllocateSendPacket")
	procWintunEndSession           = modwintun.NewProc("WintunEndSession")
	procWintunGetReadWaitEvent     = modwintun.NewProc("WintunGetReadWaitEvent")
	procWintunReceivePacket        = modwintun.NewProc("WintunReceivePacket")
	procWintunReleaseReceivePacket = modwintun.NewProc("WintunReleaseReceivePacket")
	procWintunSendPacket           = modwintun.NewProc("WintunSendPacket")
	procWintunStartSession         = modwintun.NewProc("WintunStartSession")
)

func (wintun *Adapter) StartSession(capacity uint32) (session Session, err error) {
	r0, _, e1 := syscall.Syscall(procWintunStartSession.Addr(), 2, uintptr(wintun.handle), uintptr(capacity), 0)
	if r0 == 0 {
		err = e1
	} else {
		session = Session{r0}
	}
	return
}

func (session Session) End() {
	syscall.Syscall(procWintunEndSession.Addr(), 1, session.handle, 0, 0)
	session.handle = 0
}

func (session Session) ReadWaitEvent() (handle windows.Handle) {
	r0, _, _ := syscall.Syscall(procWintunGetReadWaitEvent.Addr(), 1, session.handle, 0, 0)
	handle = windows.Handle(r0)
	return
}

func (session Session) ReceivePacket() (packet []byte, err error) {
	var packetSize uint32
	r0, _, e1 := syscall.Syscall(procWintunReceivePacket.Addr(), 2, session.handle, uintptr(unsafe.Pointer(&packetSize)), 0)
	if r0 == 0 {
		err = e1
		return
	}
	unsafeSlice(unsafe.Pointer(&packet), unsafe.Pointer(r0), int(packetSize))
	return
}

func (session Session) ReleaseReceivePacket(packet []byte) {
	syscall.Syscall(procWintunReleaseReceivePacket.Addr(), 2, session.handle, uintptr(unsafe.Pointer(&packet[0])), 0)
}

func (session Session) AllocateSendPacket(packetSize int) (packet []byte, err error) {
	r0, _, e1 := syscall.Syscall(procWintunAllocateSendPacket.Addr(), 2, session.handle, uintptr(packetSize), 0)
	if r0 == 0 {
		err = e1
		return
	}
	unsafeSlice(unsafe.Pointer(&packet), unsafe.Pointer(r0), int(packetSize))
	return
}

func (session Session) SendPacket(packet []byte) {
	syscall.Syscall(procWintunSendPacket.Addr(), 2, session.handle, uintptr(unsafe.Pointer(&packet[0])), 0)
}

// unsafeSlice updates the slice slicePtr to be a slice
// referencing the provided data with its length & capacity set to
// lenCap.
//
// TODO: when Go 1.16 or Go 1.17 is the minimum supported version,
// update callers to use unsafe.Slice instead of this.
func unsafeSlice(slicePtr, data unsafe.Pointer, lenCap int) {
	type sliceHeader struct {
		Data unsafe.Pointer
		Len  int
		Cap  int
	}
	h := (*sliceHeader)(slicePtr)
	h.Data = data
	h.Len = lenCap
	h.Cap = lenCap
}

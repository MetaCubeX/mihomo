//go:build windows && (amd64 || 386)

// Package windivert provides packet interception through the WinDivert 2.2 driver.
package windivert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Layouts and IOCTLs follow WinDivert/include/windivert_device.h (2.2).
const (
	ioctlInitialize = 0x12e486
	ioctlStartup    = 0x12e489
	ioctlRecv       = 0x12648e
	ioctlSend       = 0x12e491
	accept          = 0x7ffe
	reject          = 0x7fff
)

type address struct {
	Timestamp int64
	Flags     uint32
	Reserved  uint32
	IfIdx     uint32
	SubIfIdx  uint32
	Padding   [56]byte
}

type instruction struct {
	FieldTestSuccess uint32
	Failure          uint32
	Arg              [4]uint32
}

func equal(field uint32, value uint32, yes, no uint16) instruction {
	return instruction{FieldTestSuccess: field | uint32(yes)<<16, Failure: uint32(no), Arg: [4]uint32{value}}
}

// outbound and !loopback and !impostor and (tcp or udp).
var networkFilter = []instruction{
	equal(2, 1, 1, reject),
	equal(58, 0, 2, reject),
	equal(59, 0, 3, reject),
	equal(8, 1, accept, 4),
	equal(9, 1, accept, reject),
}

type handle struct {
	mu      sync.Mutex
	value   windows.Handle
	closed  bool
	receive ioOperation
	sendIO  ioOperation
}

type ioOperation struct {
	mu      sync.Mutex
	overlap windows.Overlapped
	args    [16]byte
	data    []byte
}

func openHandle() (*handle, error) {
	path := windows.StringToUTF16Ptr(`\\.\WinDivert`)
	open := func() (windows.Handle, error) {
		return windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED, 0)
	}
	v, err := open()
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		if err = installDriver(); err != nil {
			return nil, fmt.Errorf("load WinDivert driver (administrator required): %w", err)
		}
		v, err = open()
	}
	if err != nil {
		return nil, fmt.Errorf("open WinDivert: %w", err)
	}
	h := &handle{value: v}
	for _, operation := range []*ioOperation{&h.receive, &h.sendIO} {
		operation.overlap.HEvent, err = windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			h.close()
			return nil, fmt.Errorf("create WinDivert I/O event: %w", err)
		}
	}
	var args [16]byte
	binary.LittleEndian.PutUint32(args[4:], 30000) // priority zero, biased by PRIORITY_MAX
	var version [64]byte
	binary.LittleEndian.PutUint64(version[:], 0x4c4c447669645724)
	binary.LittleEndian.PutUint32(version[8:], 2)
	binary.LittleEndian.PutUint32(version[12:], 2)
	binary.LittleEndian.PutUint32(version[16:], uint32(unsafe.Sizeof(uintptr(0))*8))
	if _, err = h.ioctl(ioctlInitialize, &args, version[:]); err == nil {
		if binary.LittleEndian.Uint64(version[:]) != 0x5359537669645723 ||
			binary.LittleEndian.Uint32(version[8:]) != 2 || binary.LittleEndian.Uint32(version[12:]) != 2 {
			err = fmt.Errorf("expected WinDivert driver ABI 2.2")
		}
	}
	if err != nil {
		h.close()
		return nil, fmt.Errorf("initialize WinDivert: %w", err)
	}
	return h, nil
}

func (h *handle) start() error {
	var args [16]byte
	binary.LittleEndian.PutUint64(args[:], 0x20|0x40|0x80) // outbound, IPv4, IPv6
	filter := make([]byte, 24*len(networkFilter))
	for i, ins := range networkFilter {
		b := filter[i*24:]
		binary.LittleEndian.PutUint32(b, ins.FieldTestSuccess)
		binary.LittleEndian.PutUint32(b[4:], ins.Failure)
		for j, arg := range ins.Arg {
			binary.LittleEndian.PutUint32(b[8+4*j:], arg)
		}
	}
	_, err := h.ioctl(ioctlStartup, &args, filter)
	return err
}

func (h *handle) ioctl(code uint32, args *[16]byte, data []byte) (uint32, error) {
	operation := &h.sendIO
	if code == ioctlRecv {
		operation = &h.receive
	}
	operation.mu.Lock()
	defer operation.mu.Unlock()
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return 0, windows.ERROR_OPERATION_ABORTED
	}
	overlap := &operation.overlap
	*overlap = windows.Overlapped{HEvent: overlap.HEvent}
	// Keep the buffers on the heap until overlapped I/O completes.
	operation.args, operation.data = *args, data
	var n uint32
	var p *byte
	if len(data) > 0 {
		p = &data[0]
	}
	err := windows.DeviceIoControl(h.value, code, &operation.args[0], 16, p, uint32(len(data)), &n, overlap)
	h.mu.Unlock()
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		err = windows.GetOverlappedResult(h.value, overlap, &n, true)
	}
	operation.data = nil
	return n, err
}

func (h *handle) recv(packet []byte, addr *address) (int, error) {
	return h.packetIO(ioctlRecv, packet, uintptr(unsafe.Pointer(addr)))
}

func (h *handle) send(packet []byte, addr *address) (int, error) {
	return h.packetIO(ioctlSend, packet, uintptr(unsafe.Pointer(addr)))
}

// Keep the nested address pointer on the heap until overlapped I/O completes.
//
//go:uintptrescapes
func (h *handle) packetIO(code uint32, packet []byte, addr uintptr) (int, error) {
	var args [16]byte
	binary.LittleEndian.PutUint64(args[:], uint64(addr))
	if code == ioctlSend {
		binary.LittleEndian.PutUint64(args[8:], uint64(unsafe.Sizeof(address{})))
	}
	n, err := h.ioctl(code, &args, packet)
	return int(n), err
}

func (h *handle) close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	windows.CancelIoEx(h.value, nil)
	h.mu.Unlock()
	operations := []*ioOperation{&h.receive, &h.sendIO}
	// Each operation holds its lock through completion, including cancellation.
	for _, operation := range operations {
		operation.mu.Lock()
		defer operation.mu.Unlock()
	}
	windows.CloseHandle(h.value)
	for _, operation := range operations {
		if operation.overlap.HEvent != 0 {
			windows.CloseHandle(operation.overlap.HEvent)
		}
	}
}

//go:build windows
// +build windows

// Modified from: https://git.zx2c4.com/wireguard-go/tree/tun/tun_windows.go and https://git.zx2c4.com/wireguard-windows/tree/tunnel/addressconfig.go
// SPDX-License-Identifier: MIT

package dev

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"
	_ "unsafe"

	"github.com/Dreamacro/clash/listener/tun/dev/wintun"
	"golang.org/x/sys/windows"
)

const (
	rateMeasurementGranularity = uint64((time.Second / 2) / time.Nanosecond)
	spinloopRateThreshold      = 800000000 / 8                                   // 800mbps
	spinloopDuration           = uint64(time.Millisecond / 80 / time.Nanosecond) // ~1gbit/s
)

type rateJuggler struct {
	current       uint64
	nextByteCount uint64
	nextStartTime int64
	changing      int32
}

var WintunTunnelType = "Clash"
var WintunStaticRequestedGUID *windows.GUID

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

//go:linkname nanotime runtime.nanotime
func nanotime() int64

func (tun *tunWindows) Close() error {
	var err error
	tun.closeOnce.Do(func() {
		atomic.StoreInt32(&tun.close, 1)
		windows.SetEvent(tun.readWait)
		//tun.running.Wait()
		tun.session.End()
		if tun.wt != nil {
			err = tun.wt.Close()
		}
	})
	return err
}

func (tun *tunWindows) MTU() (int, error) {
	return tun.forcedMTU, nil
}

// TODO: This is a temporary hack. We really need to be monitoring the interface in real time and adapting to MTU changes.
func (tun *tunWindows) ForceMTU(mtu int) {
	tun.forcedMTU = mtu
}

// Note: Read() and Write() assume the caller comes only from a single thread; there's no locking.

func (tun *tunWindows) Read0(buff []byte, offset int) (int, error) {
	tun.running.Add(1)
	defer tun.running.Done()
retry:
	if atomic.LoadInt32(&tun.close) == 1 {
		return 0, os.ErrClosed
	}
	start := nanotime()
	shouldSpin := atomic.LoadUint64(&tun.rate.current) >= spinloopRateThreshold && uint64(start-atomic.LoadInt64(&tun.rate.nextStartTime)) <= rateMeasurementGranularity*2
	for {
		if atomic.LoadInt32(&tun.close) == 1 {
			return 0, os.ErrClosed
		}
		packet, err := tun.session.ReceivePacket()
		switch err {
		case nil:
			packetSize := len(packet)
			copy(buff[offset:], packet)
			tun.session.ReleaseReceivePacket(packet)
			tun.rate.update(uint64(packetSize))
			return packetSize, nil
		case windows.ERROR_NO_MORE_ITEMS:
			if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
				windows.WaitForSingleObject(tun.readWait, windows.INFINITE)
				goto retry
			}
			procyield(1)
			continue
		case windows.ERROR_HANDLE_EOF:
			return 0, os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			return 0, errors.New("Send ring corrupt")
		}
		return 0, fmt.Errorf("Read failed: %w", err)
	}
}

func (tun *tunWindows) Flush() error {
	return nil
}

func (tun *tunWindows) Write0(buff []byte, offset int) (int, error) {
	tun.running.Add(1)
	defer tun.running.Done()
	if atomic.LoadInt32(&tun.close) == 1 {
		return 0, os.ErrClosed
	}

	packetSize := len(buff) - offset
	tun.rate.update(uint64(packetSize))

	packet, err := tun.session.AllocateSendPacket(packetSize)
	if err == nil {
		copy(packet, buff[offset:])
		tun.session.SendPacket(packet)
		return packetSize, nil
	}
	switch err {
	case windows.ERROR_HANDLE_EOF:
		return 0, os.ErrClosed
	case windows.ERROR_BUFFER_OVERFLOW:
		return 0, nil // Dropping when ring is full.
	}
	return 0, fmt.Errorf("Write failed: %w", err)
}

// LUID returns Windows interface instance ID.
func (tun *tunWindows) LUID() uint64 {
	tun.running.Add(1)
	defer tun.running.Done()
	if atomic.LoadInt32(&tun.close) == 1 {
		return 0
	}
	return tun.wt.LUID()
}

// RunningVersion returns the running version of the Wintun driver.
func (tun *tunWindows) RunningVersion() (version uint32, err error) {
	return wintun.RunningVersion()
}

func (rate *rateJuggler) update(packetLen uint64) {
	now := nanotime()
	total := atomic.AddUint64(&rate.nextByteCount, packetLen)
	period := uint64(now - atomic.LoadInt64(&rate.nextStartTime))
	if period >= rateMeasurementGranularity {
		if !atomic.CompareAndSwapInt32(&rate.changing, 0, 1) {
			return
		}
		atomic.StoreInt64(&rate.nextStartTime, now)
		atomic.StoreUint64(&rate.current, total*uint64(time.Second/time.Nanosecond)/period)
		atomic.StoreUint64(&rate.nextByteCount, 0)
		atomic.StoreInt32(&rate.changing, 0)
	}
}

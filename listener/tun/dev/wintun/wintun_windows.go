package wintun

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/Dreamacro/clash/log"
	"golang.org/x/sys/windows"
)

type loggerLevel int

const (
	logInfo loggerLevel = iota
	logWarn
	logErr
)

const (
	PoolNameMax    = 256
	AdapterNameMax = 128
)

type Pool [PoolNameMax]uint16
type Adapter struct {
	handle uintptr
}

var (
	modwintun = newLazyDLL("wintun.dll", setupLogger)

	procWintunCreateAdapter           = modwintun.NewProc("WintunCreateAdapter")
	procWintunDeleteAdapter           = modwintun.NewProc("WintunDeleteAdapter")
	procWintunDeletePoolDriver        = modwintun.NewProc("WintunDeletePoolDriver")
	procWintunEnumAdapters            = modwintun.NewProc("WintunEnumAdapters")
	procWintunFreeAdapter             = modwintun.NewProc("WintunFreeAdapter")
	procWintunOpenAdapter             = modwintun.NewProc("WintunOpenAdapter")
	procWintunGetAdapterLUID          = modwintun.NewProc("WintunGetAdapterLUID")
	procWintunGetAdapterName          = modwintun.NewProc("WintunGetAdapterName")
	procWintunGetRunningDriverVersion = modwintun.NewProc("WintunGetRunningDriverVersion")
	procWintunSetAdapterName          = modwintun.NewProc("WintunSetAdapterName")
)

func setupLogger(dll *lazyDLL) {
	syscall.Syscall(dll.NewProc("WintunSetLogger").Addr(), 1, windows.NewCallback(func(level loggerLevel, msg *uint16) int {
		var lv log.LogLevel
		switch level {
		case logInfo:
			lv = log.INFO
		case logWarn:
			lv = log.WARNING
		case logErr:
			lv = log.ERROR
		default:
			lv = log.INFO
		}
		log.PrintLog(lv, "[Wintun] %s", windows.UTF16PtrToString(msg))
		return 0
	}), 0, 0)
}

func MakePool(poolName string) (pool *Pool, err error) {
	poolName16, err := windows.UTF16FromString(poolName)
	if err != nil {
		return
	}
	if len(poolName16) > PoolNameMax {
		err = errors.New("Pool name too long")
		return
	}
	pool = &Pool{}
	copy(pool[:], poolName16)
	return
}

func (pool *Pool) String() string {
	return windows.UTF16ToString(pool[:])
}

func freeAdapter(wintun *Adapter) {
	syscall.Syscall(procWintunFreeAdapter.Addr(), 1, uintptr(wintun.handle), 0, 0)
}

// OpenAdapter finds a Wintun adapter by its name. This function returns the adapter if found, or
// windows.ERROR_FILE_NOT_FOUND otherwise. If the adapter is found but not a Wintun-class or a
// member of the pool, this function returns windows.ERROR_ALREADY_EXISTS. The adapter must be
// released after use.
func (pool *Pool) OpenAdapter(ifname string) (wintun *Adapter, err error) {
	ifname16, err := windows.UTF16PtrFromString(ifname)
	if err != nil {
		return nil, err
	}
	r0, _, e1 := syscall.Syscall(procWintunOpenAdapter.Addr(), 2, uintptr(unsafe.Pointer(pool)), uintptr(unsafe.Pointer(ifname16)), 0)
	if r0 == 0 {
		err = e1
		return
	}
	wintun = &Adapter{r0}
	runtime.SetFinalizer(wintun, freeAdapter)
	return
}

// CreateAdapter creates a Wintun adapter. ifname is the requested name of the adapter, while
// requestedGUID is the GUID of the created network adapter, which then influences NLA generation
// deterministically. If it is set to nil, the GUID is chosen by the system at random, and hence a
// new NLA entry is created for each new adapter. It is called "requested" GUID because the API it
// uses is completely undocumented, and so there could be minor interesting complications with its
// usage. This function returns the network adapter ID and a flag if reboot is required.
func (pool *Pool) CreateAdapter(ifname string, requestedGUID *windows.GUID) (wintun *Adapter, rebootRequired bool, err error) {
	var ifname16 *uint16
	ifname16, err = windows.UTF16PtrFromString(ifname)
	if err != nil {
		return
	}
	var _p0 uint32
	r0, _, e1 := syscall.Syscall6(procWintunCreateAdapter.Addr(), 4, uintptr(unsafe.Pointer(pool)), uintptr(unsafe.Pointer(ifname16)), uintptr(unsafe.Pointer(requestedGUID)), uintptr(unsafe.Pointer(&_p0)), 0, 0)
	rebootRequired = _p0 != 0
	if r0 == 0 {
		err = e1
		return
	}
	wintun = &Adapter{r0}
	runtime.SetFinalizer(wintun, freeAdapter)
	return
}

// Delete deletes a Wintun adapter. This function succeeds if the adapter was not found. It returns
// a bool indicating whether a reboot is required.
func (wintun *Adapter) Delete(forceCloseSessions bool) (rebootRequired bool, err error) {
	var _p0 uint32
	if forceCloseSessions {
		_p0 = 1
	}
	var _p1 uint32
	r1, _, e1 := syscall.Syscall(procWintunDeleteAdapter.Addr(), 3, uintptr(wintun.handle), uintptr(_p0), uintptr(unsafe.Pointer(&_p1)))
	rebootRequired = _p1 != 0
	if r1 == 0 {
		err = e1
	}
	return
}

// DeleteMatchingAdapters deletes all Wintun adapters, which match
// given criteria, and returns which ones it deleted, whether a reboot
// is required after, and which errors occurred during the process.
func (pool *Pool) DeleteMatchingAdapters(matches func(adapter *Adapter) bool, forceCloseSessions bool) (rebootRequired bool, errors []error) {
	cb := func(handle uintptr, _ uintptr) int {
		adapter := &Adapter{handle}
		if !matches(adapter) {
			return 1
		}
		rebootRequired2, err := adapter.Delete(forceCloseSessions)
		if err != nil {
			errors = append(errors, err)
			return 1
		}
		rebootRequired = rebootRequired || rebootRequired2
		return 1
	}
	r1, _, e1 := syscall.Syscall(procWintunEnumAdapters.Addr(), 3, uintptr(unsafe.Pointer(pool)), uintptr(windows.NewCallback(cb)), 0)
	if r1 == 0 {
		errors = append(errors, e1)
	}
	return
}

// Name returns the name of the Wintun adapter.
func (wintun *Adapter) Name() (ifname string, err error) {
	var ifname16 [AdapterNameMax]uint16
	r1, _, e1 := syscall.Syscall(procWintunGetAdapterName.Addr(), 2, uintptr(wintun.handle), uintptr(unsafe.Pointer(&ifname16[0])), 0)
	if r1 == 0 {
		err = e1
		return
	}
	ifname = windows.UTF16ToString(ifname16[:])
	return
}

// DeleteDriver deletes all Wintun adapters in a pool and if there are no more adapters in any other
// pools, also removes Wintun from the driver store, usually called by uninstallers.
func (pool *Pool) DeleteDriver() (rebootRequired bool, err error) {
	var _p0 uint32
	r1, _, e1 := syscall.Syscall(procWintunDeletePoolDriver.Addr(), 2, uintptr(unsafe.Pointer(pool)), uintptr(unsafe.Pointer(&_p0)), 0)
	rebootRequired = _p0 != 0
	if r1 == 0 {
		err = e1
	}
	return

}

// SetName sets name of the Wintun adapter.
func (wintun *Adapter) SetName(ifname string) (err error) {
	ifname16, err := windows.UTF16FromString(ifname)
	if err != nil {
		return err
	}
	r1, _, e1 := syscall.Syscall(procWintunSetAdapterName.Addr(), 2, uintptr(wintun.handle), uintptr(unsafe.Pointer(&ifname16[0])), 0)
	if r1 == 0 {
		err = e1
	}
	return
}

// RunningVersion returns the version of the running Wintun driver.
func RunningVersion() (version uint32, err error) {
	r0, _, e1 := syscall.Syscall(procWintunGetRunningDriverVersion.Addr(), 0, 0, 0, 0)
	version = uint32(r0)
	if version == 0 {
		err = e1
	}
	return
}

// LUID returns the LUID of the adapter.
func (wintun *Adapter) LUID() (luid uint64) {
	syscall.Syscall(procWintunGetAdapterLUID.Addr(), 2, uintptr(wintun.handle), uintptr(unsafe.Pointer(&luid)), 0)
	return
}

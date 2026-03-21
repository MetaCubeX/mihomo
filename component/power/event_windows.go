package power

// modify from https://github.com/golang/go/blob/b634f6fdcbebee23b7da709a243f3db217b64776/src/runtime/os_windows.go#L257

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	libPowrProf                              = windows.NewLazySystemDLL("powrprof.dll")
	powerRegisterSuspendResumeNotification   = libPowrProf.NewProc("PowerRegisterSuspendResumeNotification")
	powerUnregisterSuspendResumeNotification = libPowrProf.NewProc("PowerUnregisterSuspendResumeNotification")
)

func NewEventListener(cb func(Type)) (func(), error) {
	if err := powerRegisterSuspendResumeNotification.Find(); err != nil {
		return nil, err // Running on Windows 7, where we don't need it anyway.
	}
	if err := powerUnregisterSuspendResumeNotification.Find(); err != nil {
		return nil, err // Running on Windows 7, where we don't need it anyway.
	}

	// Defines the type of event
	const (
		PBT_APMSUSPEND         uint32 = 4
		PBT_APMRESUMESUSPEND   uint32 = 7
		PBT_APMRESUMEAUTOMATIC uint32 = 18
	)

	const (
		_DEVICE_NOTIFY_CALLBACK = 2
	)
	type _DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS struct {
		callback uintptr
		context  uintptr
	}

	var fn interface{} = func(context uintptr, changeType uint32, setting uintptr) uintptr {
		switch changeType {
		case PBT_APMSUSPEND:
			cb(SUSPEND)
		case PBT_APMRESUMESUSPEND:
			cb(RESUME)
		case PBT_APMRESUMEAUTOMATIC:
			cb(RESUMEAUTOMATIC)
		}
		return 0
	}

	params := _DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS{
		callback: windows.NewCallback(fn),
	}
	handle := uintptr(0)

	// DWORD PowerRegisterSuspendResumeNotification(
	//  [in]  DWORD         Flags,
	//  [in]  HANDLE        Recipient,
	//  [out] PHPOWERNOTIFY RegistrationHandle
	//);
	_, _, err := powerRegisterSuspendResumeNotification.Call(
		_DEVICE_NOTIFY_CALLBACK,
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if err != nil {
		return nil, err
	}

	return func() {
		// DWORD PowerUnregisterSuspendResumeNotification(
		//  [in, out] HPOWERNOTIFY RegistrationHandle
		//);
		_, _, _ = powerUnregisterSuspendResumeNotification.Call(
			handle,
		)
		runtime.KeepAlive(params)
		runtime.KeepAlive(handle)
	}, nil
}

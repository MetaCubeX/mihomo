//go:build windows && (amd64 || 386)

package windivert

import (
	"bytes"
	_ "embed"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

//go:embed driver/WinDivert64.sys
var driver64 []byte

//go:embed driver/WinDivert32.sys
var driver32 []byte

func installDriver() error {
	// Match WinDivert's installer mutex, also coordinating with other users.
	mutex, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr("WinDivertDriverInstallMutex"))
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	defer windows.CloseHandle(mutex)
	if _, err = windows.WaitForSingleObject(mutex, windows.INFINITE); err != nil {
		return err
	}
	defer windows.ReleaseMutex(mutex)
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService("WinDivert")
	created := false
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		data, name := driver64, "WinDivert64.sys"
		if runtime.GOARCH == "386" {
			var wow64 bool
			if err = windows.IsWow64Process(windows.CurrentProcess(), &wow64); err != nil {
				return err
			}
			if !wow64 {
				data, name = driver32, "WinDivert32.sys"
			}
		}
		cache, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_CREATE)
		if err != nil {
			return err
		}
		dir := filepath.Join(cache, "mihomo", "windivert", "2.2.2")
		if err = os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		path := filepath.Join(dir, name)
		if existing, _ := os.ReadFile(path); !bytes.Equal(existing, data) {
			if err = os.WriteFile(path, data, 0600); err != nil {
				return err
			}
		}
		service, err = manager.CreateService("WinDivert", path, mgr.Config{
			ServiceType:  windows.SERVICE_KERNEL_DRIVER,
			StartType:    mgr.StartManual,
			ErrorControl: mgr.ErrorNormal,
		})
		if err != nil {
			return err
		}
		created = true
	} else if err != nil {
		return err
	}
	defer func() {
		if created {
			service.Delete()
		}
		service.Close()
	}()
	if err = service.Start(); errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return nil
	}
	return err
}

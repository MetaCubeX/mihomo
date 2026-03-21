package hosts

// this file copy and modify from golang's std net/hook_windows.go

import (
	"golang.org/x/sys/windows"
)

func init() {
	if dir, err := windows.GetSystemDirectory(); err == nil {
		hostsFilePath = dir + "/Drivers/etc/hosts"
	}
}

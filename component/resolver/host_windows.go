//go:build !go1.22

// a simple standard lib fix from: https://github.com/golang/go/commit/33d4a5105cf2b2d549922e909e9239a48b8cefcc

package resolver

import (
	"golang.org/x/sys/windows"
	_ "unsafe"
)

//go:linkname testHookHostsPath net.testHookHostsPath
var testHookHostsPath string

func init() {
	if dir, err := windows.GetSystemDirectory(); err == nil {
		testHookHostsPath = dir + "/Drivers/etc/hosts"
	}
}

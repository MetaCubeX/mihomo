package features

import "golang.org/x/sys/windows"

func init() {
	version := windows.RtlGetVersion()
	WindowsMajorVersion = version.MajorVersion
	WindowsMinorVersion = version.MinorVersion
	WindowsBuildNumber = version.BuildNumber
}

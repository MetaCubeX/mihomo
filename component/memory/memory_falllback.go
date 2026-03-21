//go:build !darwin && !linux && !freebsd && !openbsd && !windows

package memory

func GetMemoryInfo(pid int32) (*MemoryInfoStat, error) {
	return nil, ErrNotImplementedError
}

package memory

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var pageSize = uint64(os.Getpagesize())

func GetMemoryInfo(pid int32) (*MemoryInfoStat, error) {
	proc := os.Getenv("HOST_PROC")
	if proc == "" {
		proc = "/proc"
	}
	memPath := filepath.Join(proc, strconv.Itoa(int(pid)), "statm")
	contents, err := os.ReadFile(memPath)
	if err != nil {
		return nil, err
	}
	fields := strings.Split(string(contents), " ")

	vms, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return nil, err
	}
	rss, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return nil, err
	}
	memInfo := &MemoryInfoStat{
		RSS: rss * pageSize,
		VMS: vms * pageSize,
	}
	return memInfo, nil
}

// Package memory return MemoryInfoStat
// modify from https://github.com/shirou/gopsutil/tree/v4.25.8/process
package memory

import (
	"errors"
	"fmt"
	"math"
)

var ErrNotImplementedError = errors.New("not implemented yet")

type MemoryInfoStat struct {
	RSS uint64 `json:"rss"` // bytes
	VMS uint64 `json:"vms"` // bytes
}

// PrettyByteSize convert size in bytes to Bytes, Kilobytes, Megabytes, GB and TB
// https://gist.github.com/anikitenko/b41206a49727b83a530142c76b1cb82d?permalink_comment_id=4467913#gistcomment-4467913
func PrettyByteSize(b uint64) string {
	bf := float64(b)
	for _, unit := range []string{"", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"} {
		if math.Abs(bf) < 1024.0 {
			return fmt.Sprintf("%3.1f%sB", bf, unit)
		}
		bf /= 1024.0
	}
	return fmt.Sprintf("%.1fYiB", bf)
}

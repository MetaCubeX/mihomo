//go:build !unix && !windows

package fragment

const oobSupported = false

func sendOOB(fd uintptr, b []byte) (int, error) {
	return 0, nil
}

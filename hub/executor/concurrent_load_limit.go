//go:build !386 && !amd64 && !arm64 && !arm64be && !mipsle && !mips

package executor

const concurrentCount = 5

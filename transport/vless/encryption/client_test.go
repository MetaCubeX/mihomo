package encryption

import (
	"fmt"
	"runtime"
	"testing"
)

func TestHasAESGCMHardwareSupport(t *testing.T) {
	fmt.Println("HasAESGCMHardwareSupport:", HasAESGCMHardwareSupport)

	if runtime.GOARCH == "arm64" && runtime.GOOS == "darwin" {
		// It should be supported starting from Apple Silicon M1
		// https://github.com/golang/go/blob/go1.25.0/src/internal/cpu/cpu_arm64_darwin.go#L26-L30
		if !HasAESGCMHardwareSupport {
			t.Errorf("For ARM64 Darwin platforms (excluding iOS), AES GCM hardware acceleration should always be available.")
		}
	}
}

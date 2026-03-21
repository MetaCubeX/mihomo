//go:build !go1.21

package vmess

// Golang1.20's net.http Flush will mistakenly call w.WriteHeader(StatusOK) internally after w.WriteHeader(http.StatusSwitchingProtocols)
// https://github.com/golang/go/issues/59564
const writeHeaderShouldFlush = false

//go:build !build_local && cgo
// +build !build_local,cgo

package script

/*
#cgo linux,amd64 pkg-config: python3-embed

#cgo darwin,amd64 CFLAGS: -I/build/python/python-3.9.7-darwin-amd64/include/python3.9
#cgo darwin,arm64 CFLAGS: -I/build/python/python-3.9.7-darwin-arm64/include/python3.9
#cgo windows,amd64 CFLAGS: -I/build/python/python-3.9.7-windows-amd64/include -DMS_WIN64
#cgo windows,386 CFLAGS: -I/build/python/python-3.9.7-windows-386/include
//#cgo linux,amd64 CFLAGS: -I/home/runner/work/clash/clash/bin/python/python-3.9.7-linux-amd64/include/python3.9
//#cgo linux,arm64 CFLAGS: -I/build/python/python-3.9.7-linux-arm64/include/python3.9
//#cgo linux,386 CFLAGS: -I/build/python/python-3.9.7-linux-386/include/python3.9

#cgo darwin,amd64 LDFLAGS: -L/build/python/python-3.9.7-darwin-amd64/lib -lpython3.9 -ldl   -framework CoreFoundation
#cgo darwin,arm64 LDFLAGS: -L/build/python/python-3.9.7-darwin-arm64/lib -lpython3.9 -ldl   -framework CoreFoundation
#cgo windows,amd64 LDFLAGS: -L/build/python/python-3.9.7-windows-amd64/lib -lpython39 -lpthread -lm
#cgo windows,386 LDFLAGS: -L/build/python/python-3.9.7-windows-386/lib -lpython39 -lpthread -lm
//#cgo linux,amd64 LDFLAGS: -L/home/runner/work/clash/clash/bin/python/python-3.9.7-linux-amd64/lib -lpython3.9 -lpthread -ldl  -lutil -lm
//#cgo linux,arm64 LDFLAGS: -L/build/python/python-3.9.7-linux-arm64/lib -lpython3.9 -lpthread -ldl  -lutil -lm
//#cgo linux,386 LDFLAGS: -L/build/python/python-3.9.7-linux-386/lib -lpython3.9 -lpthread -ldl  -lutil -lm
*/
import "C"

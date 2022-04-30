//go:build build_actions

package script

/*
#cgo windows,amd64 CFLAGS: -ID:/python-amd64/include -DMS_WIN64

#cgo windows,amd64 LDFLAGS: -LD:/python-amd64/libs -lpython39 -lpthread -lm
*/
import "C"

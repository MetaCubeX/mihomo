package inbound

import (
	"net"

	"github.com/metacubex/wireguard-go/ipc/namedpipe"
	"golang.org/x/sys/windows"
)

const SupportNamedPipe = true

// windowsSDDL is the Security Descriptor set on the namedpipe.
// It provides read/write access to all users and the local system.
const windowsSDDL = "D:PAI(A;OICI;GWGR;;;BU)(A;OICI;GWGR;;;SY)"

func ListenNamedPipe(path string) (net.Listener, error) {
	securityDescriptor, err := windows.SecurityDescriptorFromString(windowsSDDL)
	if err != nil {
		return nil, err
	}
	namedpipeLC := namedpipe.ListenConfig{
		SecurityDescriptor: securityDescriptor,
		InputBufferSize:    256 * 1024,
		OutputBufferSize:   256 * 1024,
	}
	return namedpipeLC.Listen(path)
}

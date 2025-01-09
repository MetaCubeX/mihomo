package inbound

import (
	"net"
	"os"

	"github.com/metacubex/wireguard-go/ipc/namedpipe"
	"golang.org/x/sys/windows"
)

const SupportNamedPipe = true

// windowsSDDL is the Security Descriptor set on the namedpipe.
// It provides read/write access to all users and the local system.
const windowsSDDL = "D:PAI(A;OICI;GWGR;;;BU)(A;OICI;GWGR;;;SY)"

func ListenNamedPipe(path string) (net.Listener, error) {
	sddl := os.Getenv("LISTEN_NAMEDPIPE_SDDL")
	if sddl == "" {
		sddl = windowsSDDL
	}
	securityDescriptor, err := windows.SecurityDescriptorFromString(sddl)
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

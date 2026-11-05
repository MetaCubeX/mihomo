package singsnell

import (
	"io"

	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
)

type Request struct {
	Command     byte
	ClientID    []byte
	Destination M.Socksaddr
}

func (r Request) Write(buffer *buf.Buffer) error {
	if len(r.ClientID) > 255 {
		return E.New("snell: client id too long")
	}
	_, err := buffer.Write([]byte{RequestVersion, r.Command, byte(len(r.ClientID))})
	if err != nil {
		return err
	}
	if len(r.ClientID) > 0 {
		_, err = buffer.Write(r.ClientID)
		if err != nil {
			return err
		}
	}
	switch r.Command {
	case CommandConnect, CommandConnectV2:
		return WriteConnectAddress(buffer, r.Destination)
	case CommandPing, CommandUDP:
		return nil
	default:
		return E.Extend(ErrUnsupportedCommand, r.Command)
	}
}

func (r Request) Len() int {
	requestLen := 3 + len(r.ClientID)
	switch r.Command {
	case CommandConnect, CommandConnectV2:
		return requestLen + 1 + len(r.Destination.AddrString()) + 2
	default:
		return requestLen
	}
}

func ReadRequest(reader io.Reader) (Request, error) {
	prefix := make([]byte, 3)
	_, err := io.ReadFull(reader, prefix)
	if err != nil {
		return Request{}, err
	}
	if prefix[0] != RequestVersion {
		return Request{}, E.Extend(ErrBadVersion, "request version ", prefix[0])
	}
	clientIDLen := int(prefix[2])
	request := Request{Command: prefix[1]}
	if clientIDLen > 0 {
		request.ClientID = make([]byte, clientIDLen)
		_, err = io.ReadFull(reader, request.ClientID)
		if err != nil {
			return Request{}, err
		}
	}
	switch request.Command {
	case CommandConnect, CommandConnectV2:
		request.Destination, err = ReadConnectAddress(reader)
		if err != nil {
			return Request{}, err
		}
	case CommandPing, CommandUDP:
	default:
		return Request{}, E.Extend(ErrUnsupportedCommand, request.Command)
	}
	return request, nil
}

func ReadServerError(record *buf.Buffer) error {
	errorCode, err := record.ReadByte()
	if err != nil {
		return err
	}
	message, err := M.ReadSockString(record)
	if err != nil {
		return err
	}
	// Surge 6.7.0 (11520): SNConnectorV4::socket:didReadData: rejects server-error replies unless the frame is
	// exactly code, message length, and message bytes.
	if !record.IsEmpty() {
		return E.New("snell: server error reply has trailing data")
	}
	return E.New("snell: server error ", errorCode, ": ", message)
}

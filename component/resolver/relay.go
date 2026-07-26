package resolver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/metacubex/mihomo/common/pool"

	D "github.com/miekg/dns"
)

const DefaultDnsReadTimeout = time.Second * 10
const DefaultDnsRelayTimeout = time.Second * 5

const SafeDnsPacketSize = 2 * 1024 // safe size which is 1232 from https://dnsflagday.net/2020/, so 2048 is enough

// RequestUDPSize returns the UDP payload size a reply to msg may occupy:
// the client's advertised EDNS0 buffer size, or 512 (D.MinMsgSize) without an OPT record.
func RequestUDPSize(msg *D.Msg) int {
	if opt := msg.IsEdns0(); opt != nil {
		return int(opt.UDPSize())
	}
	return D.MinMsgSize
}

func RelayDnsConn(ctx context.Context, conn net.Conn, readTimeout time.Duration) error {
	buff := pool.Get(pool.UDPBufferSize)
	defer func() {
		_ = pool.Put(buff)
		_ = conn.Close()
	}()
	for {
		if readTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		}

		length := uint16(0)
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			break
		}

		if int(length) > len(buff) {
			break
		}

		n, err := io.ReadFull(conn, buff[:length])
		if err != nil {
			break
		}

		err = func() error {
			ctx, cancel := context.WithTimeout(ctx, DefaultDnsRelayTimeout)
			defer cancel()
			inData := buff[:n]
			outBuff := buff[2:]
			msg, err := relayDnsPacket(ctx, inData, outBuff, 0)
			if err != nil {
				return err
			}

			if &msg[0] == &outBuff[0] { // msg is still in the buff
				binary.BigEndian.PutUint16(buff[:2], uint16(len(msg)))
				outBuff = buff[:2+len(msg)]
			} else { // buff not big enough (WTF???)
				newBuff := pool.Get(len(msg) + 2)
				defer pool.Put(newBuff)
				binary.BigEndian.PutUint16(newBuff[:2], uint16(len(msg)))
				copy(newBuff[2:], msg)
				outBuff = newBuff
			}

			_, err = conn.Write(outBuff)
			if err != nil {
				return err
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func relayDnsPacket(ctx context.Context, payload []byte, target []byte, maxSize int) ([]byte, error) {
	msg := &D.Msg{}
	if err := msg.Unpack(payload); err != nil {
		return nil, err
	}

	r, err := ServeMsg(ctx, msg)
	if err != nil {
		m := new(D.Msg)
		m.SetRcode(msg, D.RcodeServerFailure)
		return m.PackBuffer(target)
	}

	r.SetRcode(msg, r.Rcode)
	if maxSize > 0 { // udp
		if size := RequestUDPSize(msg); size < maxSize {
			maxSize = size
		}
		r.Truncate(maxSize)
	}
	r.Compress = true
	data, err := r.PackBuffer(target)
	if err != nil {
		return nil, err
	}
	// PackBuffer sizes its scratch space by the *uncompressed* message length and may
	// have allocated a new slice even though the compressed result fits into target.
	// Callers (e.g. the tun dns hijack) assume the result is backed by target, so copy it back.
	if len(data) > 0 && len(data) <= len(target) && &data[0] != &target[0] {
		data = target[:copy(target, data)]
	}
	return data, nil
}

// RelayDnsPacket will truncate udp message up to SafeDnsPacketSize
func RelayDnsPacket(ctx context.Context, payload []byte, target []byte) ([]byte, error) {
	return relayDnsPacket(ctx, payload, target, SafeDnsPacketSize)
}

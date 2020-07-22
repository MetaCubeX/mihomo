package obfs

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/ssr/tools"
)

type tlsAuthData struct {
	localClientID [32]byte
}

type tls12Ticket struct {
	*Base
	*tlsAuthData
	handshakeStatus int
	sendSaver       bytes.Buffer
	recvBuffer      bytes.Buffer
	buffer          bytes.Buffer
}

func init() {
	register("tls1.2_ticket_auth", newTLS12Ticket)
	register("tls1.2_ticket_fastauth", newTLS12Ticket)
}

func newTLS12Ticket(b *Base) Obfs {
	return &tls12Ticket{
		Base: b,
	}
}

func (t *tls12Ticket) initForConn() Obfs {
	r := &tls12Ticket{
		Base:        t.Base,
		tlsAuthData: &tlsAuthData{},
	}
	rand.Read(r.localClientID[:])
	return r
}

func (t *tls12Ticket) GetObfsOverhead() int {
	return 5
}

func (t *tls12Ticket) Decode(b []byte) ([]byte, bool, error) {
	if t.handshakeStatus == -1 {
		return b, false, nil
	}
	t.buffer.Reset()
	if t.handshakeStatus == 8 {
		t.recvBuffer.Write(b)
		for t.recvBuffer.Len() > 5 {
			var h [5]byte
			t.recvBuffer.Read(h[:])
			if !bytes.Equal(h[:3], []byte{0x17, 0x3, 0x3}) {
				log.Println("incorrect magic number", h[:3], ", 0x170303 is expected")
				return nil, false, errTLS12TicketAuthIncorrectMagicNumber
			}
			size := int(binary.BigEndian.Uint16(h[3:5]))
			if t.recvBuffer.Len() < size {
				// 不够读，下回再读吧
				unread := t.recvBuffer.Bytes()
				t.recvBuffer.Reset()
				t.recvBuffer.Write(h[:])
				t.recvBuffer.Write(unread)
				break
			}
			d := pool.Get(size)
			t.recvBuffer.Read(d)
			t.buffer.Write(d)
			pool.Put(d)
		}
		return t.buffer.Bytes(), false, nil
	}

	if len(b) < 11+32+1+32 {
		return nil, false, errTLS12TicketAuthTooShortData
	}

	hash := t.hmacSHA1(b[11 : 11+22])

	if !hmac.Equal(b[33:33+tools.HmacSHA1Len], hash) {
		return nil, false, errTLS12TicketAuthHMACError
	}
	return nil, true, nil
}

func (t *tls12Ticket) Encode(b []byte) ([]byte, error) {
	t.buffer.Reset()
	switch t.handshakeStatus {
	case 8:
		if len(b) < 1024 {
			d := []byte{0x17, 0x3, 0x3, 0, 0}
			binary.BigEndian.PutUint16(d[3:5], uint16(len(b)&0xFFFF))
			t.buffer.Write(d)
			t.buffer.Write(b)
			return t.buffer.Bytes(), nil
		}
		start := 0
		var l int
		for len(b)-start > 2048 {
			l = rand.Intn(4096) + 100
			if l > len(b)-start {
				l = len(b) - start
			}
			packData(&t.buffer, b[start:start+l])
			start += l
		}
		if len(b)-start > 0 {
			l = len(b) - start
			packData(&t.buffer, b[start:start+l])
		}
		return t.buffer.Bytes(), nil
	case 1:
		if len(b) > 0 {
			if len(b) < 1024 {
				packData(&t.sendSaver, b)
			} else {
				start := 0
				var l int
				for len(b)-start > 2048 {
					l = rand.Intn(4096) + 100
					if l > len(b)-start {
						l = len(b) - start
					}
					packData(&t.buffer, b[start:start+l])
					start += l
				}
				if len(b)-start > 0 {
					l = len(b) - start
					packData(&t.buffer, b[start:start+l])
				}
				io.Copy(&t.sendSaver, &t.buffer)
			}
			return []byte{}, nil
		}
		hmacData := make([]byte, 43)
		handshakeFinish := []byte("\x14\x03\x03\x00\x01\x01\x16\x03\x03\x00\x20")
		copy(hmacData, handshakeFinish)
		rand.Read(hmacData[11:33])
		h := t.hmacSHA1(hmacData[:33])
		copy(hmacData[33:], h)
		t.buffer.Write(hmacData)
		io.Copy(&t.buffer, &t.sendSaver)
		t.handshakeStatus = 8
		return t.buffer.Bytes(), nil
	case 0:
		tlsData0 := []byte("\x00\x1c\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xcc\x14\xcc\x13\xc0\x0a\xc0\x14\xc0\x09\xc0\x13\x00\x9c\x00\x35\x00\x2f\x00\x0a\x01\x00")
		tlsData1 := []byte("\xff\x01\x00\x01\x00")
		tlsData2 := []byte("\x00\x17\x00\x00\x00\x23\x00\xd0")
		// tlsData3 := []byte("\x00\x0d\x00\x16\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x12\x00\x00\x75\x50\x00\x00\x00\x0b\x00\x02\x01\x00\x00\x0a\x00\x06\x00\x04\x00\x17\x00\x18\x00\x15\x00\x66\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		tlsData3 := []byte("\x00\x0d\x00\x16\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x12\x00\x00\x75\x50\x00\x00\x00\x0b\x00\x02\x01\x00\x00\x0a\x00\x06\x00\x04\x00\x17\x00\x18")

		var tlsData [2048]byte
		tlsDataLen := 0
		copy(tlsData[0:], tlsData1)
		tlsDataLen += len(tlsData1)
		sni := t.sni(t.getHost())
		copy(tlsData[tlsDataLen:], sni)
		tlsDataLen += len(sni)
		copy(tlsData[tlsDataLen:], tlsData2)
		tlsDataLen += len(tlsData2)
		ticketLen := rand.Intn(164)*2 + 64
		tlsData[tlsDataLen-1] = uint8(ticketLen & 0xff)
		tlsData[tlsDataLen-2] = uint8(ticketLen >> 8)
		//ticketLen := 208
		rand.Read(tlsData[tlsDataLen : tlsDataLen+ticketLen])
		tlsDataLen += ticketLen
		copy(tlsData[tlsDataLen:], tlsData3)
		tlsDataLen += len(tlsData3)

		length := 11 + 32 + 1 + 32 + len(tlsData0) + 2 + tlsDataLen
		encodedData := make([]byte, length)
		pdata := length - tlsDataLen
		l := tlsDataLen
		copy(encodedData[pdata:], tlsData[:tlsDataLen])
		encodedData[pdata-1] = uint8(tlsDataLen)
		encodedData[pdata-2] = uint8(tlsDataLen >> 8)
		pdata -= 2
		l += 2
		copy(encodedData[pdata-len(tlsData0):], tlsData0)
		pdata -= len(tlsData0)
		l += len(tlsData0)
		copy(encodedData[pdata-32:], t.localClientID[:])
		pdata -= 32
		l += 32
		encodedData[pdata-1] = 0x20
		pdata--
		l++
		copy(encodedData[pdata-32:], t.packAuthData())
		pdata -= 32
		l += 32
		encodedData[pdata-1] = 0x3
		encodedData[pdata-2] = 0x3 // tls version
		pdata -= 2
		l += 2
		encodedData[pdata-1] = uint8(l)
		encodedData[pdata-2] = uint8(l >> 8)
		encodedData[pdata-3] = 0
		encodedData[pdata-4] = 1
		pdata -= 4
		l += 4
		encodedData[pdata-1] = uint8(l)
		encodedData[pdata-2] = uint8(l >> 8)
		pdata -= 2
		l += 2
		encodedData[pdata-1] = 0x1
		encodedData[pdata-2] = 0x3 // tls version
		pdata -= 2
		l += 2
		encodedData[pdata-1] = 0x16 // tls handshake
		pdata--
		l++
		packData(&t.sendSaver, b)
		t.handshakeStatus = 1
		return encodedData, nil
	default:
		return nil, fmt.Errorf("unexpected handshake status: %d", t.handshakeStatus)
	}
}

func (t *tls12Ticket) hmacSHA1(data []byte) []byte {
	key := make([]byte, len(t.Key)+32)
	copy(key, t.Key)
	copy(key[len(t.Key):], t.localClientID[:])

	sha1Data := tools.HmacSHA1(key, data)
	return sha1Data[:tools.HmacSHA1Len]
}

func (t *tls12Ticket) sni(u string) []byte {
	bURL := []byte(u)
	length := len(bURL)
	ret := make([]byte, length+9)
	copy(ret[9:9+length], bURL)
	binary.BigEndian.PutUint16(ret[7:], uint16(length&0xFFFF))
	length += 3
	binary.BigEndian.PutUint16(ret[4:], uint16(length&0xFFFF))
	length += 2
	binary.BigEndian.PutUint16(ret[2:], uint16(length&0xFFFF))
	return ret
}

func (t *tls12Ticket) getHost() string {
	host := t.Host
	if len(t.Param) > 0 {
		hosts := strings.Split(t.Param, ",")
		if len(hosts) > 0 {

			host = hosts[rand.Intn(len(hosts))]
			host = strings.TrimSpace(host)
		}
	}
	if len(host) > 0 && host[len(host)-1] >= byte('0') && host[len(host)-1] <= byte('9') && len(t.Param) == 0 {
		host = ""
	}
	return host
}

func (t *tls12Ticket) packAuthData() (ret []byte) {
	retSize := 32
	ret = make([]byte, retSize)

	now := time.Now().Unix()
	binary.BigEndian.PutUint32(ret[:4], uint32(now))

	rand.Read(ret[4 : 4+18])

	hash := t.hmacSHA1(ret[:retSize-tools.HmacSHA1Len])
	copy(ret[retSize-tools.HmacSHA1Len:], hash)

	return
}

func packData(buffer *bytes.Buffer, suffix []byte) {
	d := []byte{0x17, 0x3, 0x3, 0, 0}
	binary.BigEndian.PutUint16(d[3:5], uint16(len(suffix)&0xFFFF))
	buffer.Write(d)
	buffer.Write(suffix)
	return
}

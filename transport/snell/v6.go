package snell

import (
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
)

// Snell v6 keeps the v4 record layout (7-byte header sealed with AES-128-GCM,
// followed by the sealed payload) but wraps it in a PSK-derived "profile": the
// salt is scattered inside a padded block, every record carries an unencrypted
// prefix that doubles as the header's AAD, padding is interleaved with the
// payload ciphertext and record sizes follow a shaped schedule. The `unshaped`
// mode drops the profile layer and the `unsafe-raw` mode drops the crypto as
// well; both must match the server's configured mode.

type V6Mode int

const (
	V6ModeDefault V6Mode = iota
	V6ModeUnshaped
	V6ModeUnsafeRaw
)

func ParseV6Mode(name string) (V6Mode, error) {
	switch name {
	case "", "default":
		return V6ModeDefault, nil
	case "unshaped":
		return V6ModeUnshaped, nil
	case "unsafe-raw":
		return V6ModeUnsafeRaw, nil
	default:
		return 0, fmt.Errorf("snell v6 unknown mode: %s", name)
	}
}

func (m V6Mode) String() string {
	switch m {
	case V6ModeDefault:
		return "default"
	case V6ModeUnshaped:
		return "unshaped"
	case V6ModeUnsafeRaw:
		return "unsafe-raw"
	default:
		return fmt.Sprintf("mode(%d)", int(m))
	}
}

const (
	v6SaltSize         = 16
	v6NonceSize        = 12
	v6TagSize          = 16
	v6HeaderVersion    = 4
	v6HeaderPlainSize  = 7
	v6HeaderCipherSize = v6HeaderPlainSize + v6TagSize
	v6MaxPayload       = 0xffff
	// the official server rejects PSKs outside this range
	V6MinPSKLength = 12
	V6MaxPSKLength = 255
)

var (
	errV6BadHeader      = errors.New("snell v6 invalid record header")
	errV6RecordPadding  = errors.New("snell v6 unexpected padding in record")
	errV6PayloadTooLong = errors.New("snell v6 payload too large")
)

func ValidateV6PSK(psk []byte) error {
	if len(psk) < V6MinPSKLength || len(psk) > V6MaxPSKLength {
		return fmt.Errorf("snell v6 psk length must be between %d and %d bytes", V6MinPSKLength, V6MaxPSKLength)
	}
	return nil
}

type v6RecordReader interface {
	// readRecord returns the payload of the next record, or
	// shadowaead.ErrZeroChunk for an end-of-stream record.
	readRecord() ([]byte, error)
}

type v6RecordWriter interface {
	// write splits p into as many records as the mode requires
	write(p []byte) error
	// writePacket emits p as exactly one record
	writePacket(p []byte) error
	writeZeroChunk() error
}

type v6Conn struct {
	net.Conn
	psk     []byte
	mode    V6Mode
	profile *v6Profile

	r    v6RecordReader
	rBuf []byte
	rMux sync.Mutex

	w    v6RecordWriter
	wMux sync.Mutex
}

func newV6Conn(conn net.Conn, psk []byte, mode V6Mode) *v6Conn {
	c := &v6Conn{Conn: conn, psk: psk, mode: mode}
	if mode == V6ModeDefault {
		c.profile = newV6Profile(psk)
	}
	return c
}

func (c *v6Conn) initReader() {
	switch c.mode {
	case V6ModeUnsafeRaw:
		c.r = &v6RawReader{Reader: c.Conn}
	case V6ModeUnshaped:
		c.r = &v6UnshapedReader{Reader: c.Conn, psk: c.psk}
	default:
		c.r = &v6ShapedReader{Reader: c.Conn, psk: c.psk, profile: c.profile}
	}
}

func (c *v6Conn) initWriter() error {
	switch c.mode {
	case V6ModeUnsafeRaw:
		c.w = &v6RawWriter{Writer: c.Conn}
		return nil
	case V6ModeUnshaped:
		w, err := newV6UnshapedWriter(c.Conn, c.psk)
		if err != nil {
			return err
		}
		c.w = w
		return nil
	default:
		w, err := newV6ShapedWriter(c.Conn, c.psk, c.profile)
		if err != nil {
			return err
		}
		c.w = w
		return nil
	}
}

func (c *v6Conn) Read(b []byte) (int, error) {
	c.rMux.Lock()
	defer c.rMux.Unlock()

	if c.r == nil {
		c.initReader()
	}
	if len(c.rBuf) == 0 {
		payload, err := c.r.readRecord()
		if err != nil {
			return 0, err
		}
		c.rBuf = payload
	}
	n := copy(b, c.rBuf)
	c.rBuf = c.rBuf[n:]
	return n, nil
}

func (c *v6Conn) Write(b []byte) (int, error) {
	c.wMux.Lock()
	defer c.wMux.Unlock()

	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	if len(b) == 0 {
		return 0, c.w.writeZeroChunk()
	}
	if err := c.w.write(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *v6Conn) WritePacketFrame(b []byte) (int, error) {
	if len(b) > v6MaxPayload {
		return 0, errV6PayloadTooLong
	}
	c.wMux.Lock()
	defer c.wMux.Unlock()

	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	if err := c.w.writePacket(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *v6Conn) WriteTo(w io.Writer) (int64, error) {
	var written int64
	buf := make([]byte, v6MaxPayload)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			nw, ew := w.Write(buf[:n])
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nw != n {
				return written, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return written, err
		}
	}
}

func (c *v6Conn) ReadFrom(r io.Reader) (int64, error) {
	var read int64
	buf := make([]byte, v6MaxPayload)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			read += int64(n)
			if _, ew := c.Write(buf[:n]); ew != nil {
				return read, ew
			}
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return read, err
		}
	}
}

func v6AEAD(psk, salt []byte) (cipher.AEAD, error) {
	return aesGCM(snellKDF(psk, salt, 16))
}

func v6RandomSalt() ([]byte, error) {
	salt := make([]byte, v6SaltSize)
	if _, err := io.ReadFull(cryptorand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

func v6PutHeader(header []byte, paddingLength, payloadLength int) {
	header[0] = v6HeaderVersion
	header[1] = 0
	header[2] = 0
	binary.BigEndian.PutUint16(header[3:5], uint16(paddingLength))
	binary.BigEndian.PutUint16(header[5:7], uint16(payloadLength))
}

// v6ParseHeader validates a plain header. strict additionally requires the two
// reserved bytes to be zero, which the official server only checks outside of
// the default mode.
func v6ParseHeader(header []byte, strict bool) (paddingLength, payloadLength int, err error) {
	if header[0] != v6HeaderVersion {
		return 0, 0, errV6BadHeader
	}
	if strict && (header[1] != 0 || header[2] != 0) {
		return 0, 0, errV6BadHeader
	}
	return int(binary.BigEndian.Uint16(header[3:5])), int(binary.BigEndian.Uint16(header[5:7])), nil
}

// --- unsafe-raw ---------------------------------------------------------------

type v6RawReader struct {
	io.Reader
}

func (r *v6RawReader) readRecord() ([]byte, error) {
	var header [v6HeaderPlainSize]byte
	if _, err := io.ReadFull(r.Reader, header[:]); err != nil {
		return nil, err
	}
	paddingLength, payloadLength, err := v6ParseHeader(header[:], true)
	if err != nil {
		return nil, err
	}
	if paddingLength != 0 {
		return nil, errV6RecordPadding
	}
	if payloadLength == 0 {
		return nil, shadowaead.ErrZeroChunk
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(r.Reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

type v6RawWriter struct {
	io.Writer
}

func (w *v6RawWriter) writeRecord(payload []byte) error {
	record := make([]byte, v6HeaderPlainSize+len(payload))
	v6PutHeader(record, 0, len(payload))
	copy(record[v6HeaderPlainSize:], payload)
	_, err := w.Writer.Write(record)
	return err
}

func (w *v6RawWriter) write(p []byte) error {
	for len(p) > 0 {
		n := minInt(len(p), v6MaxPayload)
		if err := w.writeRecord(p[:n]); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

func (w *v6RawWriter) writePacket(p []byte) error {
	return w.writeRecord(p)
}

func (w *v6RawWriter) writeZeroChunk() error {
	return w.writeRecord(nil)
}

// --- unshaped -------------------------------------------------------------------

type v6UnshapedReader struct {
	io.Reader
	psk   []byte
	aead  cipher.AEAD
	nonce [v6NonceSize]byte
}

func (r *v6UnshapedReader) readRecord() ([]byte, error) {
	if r.aead == nil {
		salt := make([]byte, v6SaltSize)
		if _, err := io.ReadFull(r.Reader, salt); err != nil {
			return nil, err
		}
		aead, err := v6AEAD(r.psk, salt)
		if err != nil {
			return nil, err
		}
		r.aead = aead
	}

	headerCipher := make([]byte, v6HeaderCipherSize)
	if _, err := io.ReadFull(r.Reader, headerCipher); err != nil {
		return nil, err
	}
	header, err := r.aead.Open(headerCipher[:0], r.nonce[:], headerCipher, nil)
	incrementV4Nonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	paddingLength, payloadLength, err := v6ParseHeader(header, true)
	if err != nil {
		return nil, err
	}
	if paddingLength != 0 {
		return nil, errV6RecordPadding
	}
	if payloadLength == 0 {
		return nil, shadowaead.ErrZeroChunk
	}

	payloadCipher := make([]byte, payloadLength+v6TagSize)
	if _, err := io.ReadFull(r.Reader, payloadCipher); err != nil {
		return nil, err
	}
	payload, err := r.aead.Open(payloadCipher[:0], r.nonce[:], payloadCipher, nil)
	incrementV4Nonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	return payload, nil
}

type v6UnshapedWriter struct {
	io.Writer
	aead     cipher.AEAD
	nonce    [v6NonceSize]byte
	salt     []byte
	saltSent bool
}

func newV6UnshapedWriter(w io.Writer, psk []byte) (*v6UnshapedWriter, error) {
	salt, err := v6RandomSalt()
	if err != nil {
		return nil, err
	}
	aead, err := v6AEAD(psk, salt)
	if err != nil {
		return nil, err
	}
	return &v6UnshapedWriter{Writer: w, aead: aead, salt: salt}, nil
}

// appendRecord seals payload as one record and appends it to out.
func (w *v6UnshapedWriter) appendRecord(out []byte, payload []byte) []byte {
	start := len(out)
	out = append(out, make([]byte, v6HeaderPlainSize)...)
	v6PutHeader(out[start:], 0, len(payload))
	out = w.aead.Seal(out[:start], w.nonce[:], out[start:start+v6HeaderPlainSize], nil)
	incrementV4Nonce(w.nonce[:])
	if len(payload) > 0 {
		out = w.aead.Seal(out, w.nonce[:], payload, nil)
		incrementV4Nonce(w.nonce[:])
	}
	return out
}

func (w *v6UnshapedWriter) writeRecords(payloads [][]byte) error {
	size := 0
	if !w.saltSent {
		size += v6SaltSize
	}
	for _, payload := range payloads {
		size += v6HeaderCipherSize + len(payload)
		if len(payload) > 0 {
			size += v6TagSize
		}
	}
	out := make([]byte, 0, size)
	if !w.saltSent {
		out = append(out, w.salt...)
		w.saltSent = true
	}
	for _, payload := range payloads {
		out = w.appendRecord(out, payload)
	}
	_, err := w.Writer.Write(out)
	return err
}

func (w *v6UnshapedWriter) write(p []byte) error {
	var payloads [][]byte
	for len(p) > 0 {
		n := minInt(len(p), v6MaxPayload)
		payloads = append(payloads, p[:n])
		p = p[n:]
	}
	return w.writeRecords(payloads)
}

func (w *v6UnshapedWriter) writePacket(p []byte) error {
	return w.writeRecords([][]byte{p})
}

func (w *v6UnshapedWriter) writeZeroChunk() error {
	return w.writeRecords([][]byte{nil})
}

// --- default (shaped) ------------------------------------------------------------

type v6ShapedReader struct {
	io.Reader
	psk     []byte
	profile *v6Profile
	aead    cipher.AEAD
	nonce   [v6NonceSize]byte
	seq     uint32
}

func (r *v6ShapedReader) readRecord() ([]byte, error) {
	if r.aead == nil {
		block := make([]byte, r.profile.saltBlockLen)
		if _, err := io.ReadFull(r.Reader, block); err != nil {
			return nil, err
		}
		salt := r.profile.extractSalt(block)
		aead, err := v6AEAD(r.psk, salt[:])
		if err != nil {
			return nil, err
		}
		r.aead = aead
	}

	prefixLength := r.profile.recordPrefixLen(r.seq)
	head := make([]byte, prefixLength+v6HeaderCipherSize)
	if _, err := io.ReadFull(r.Reader, head); err != nil {
		return nil, err
	}
	prefix := head[:prefixLength]
	headerCipher := head[prefixLength:]
	header, err := r.aead.Open(headerCipher[:0], r.nonce[:], headerCipher, prefix)
	incrementV4Nonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	// the reserved header bytes are ignored in default mode
	paddingLength, payloadLength, err := v6ParseHeader(header, false)
	if err != nil {
		return nil, err
	}
	seq := r.seq
	r.seq++

	if payloadLength == 0 {
		if paddingLength > 0 {
			if _, err := io.CopyN(io.Discard, r.Reader, int64(paddingLength)); err != nil {
				return nil, err
			}
		}
		return nil, shadowaead.ErrZeroChunk
	}

	body := make([]byte, paddingLength+payloadLength+v6TagSize)
	if _, err := io.ReadFull(r.Reader, body); err != nil {
		return nil, err
	}
	padding := body[:paddingLength]
	payloadCipher := body[paddingLength:]
	r.profile.mixPaddingPayload(seq, padding, payloadCipher)
	payload, err := r.aead.Open(payloadCipher[:0], r.nonce[:], payloadCipher, padding)
	incrementV4Nonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	return payload, nil
}

type v6ShapedWriter struct {
	io.Writer
	profile       *v6Profile
	aead          cipher.AEAD
	nonce         [v6NonceSize]byte
	salt          []byte
	saltSent      bool
	seq           uint32
	chunkSize     int
	lastWriteUnix int64
}

func newV6ShapedWriter(w io.Writer, psk []byte, profile *v6Profile) (*v6ShapedWriter, error) {
	salt, err := v6RandomSalt()
	if err != nil {
		return nil, err
	}
	aead, err := v6AEAD(psk, salt)
	if err != nil {
		return nil, err
	}
	return &v6ShapedWriter{Writer: w, profile: profile, aead: aead, salt: salt}, nil
}

// payloadLimitFor advances the shaped chunk schedule and returns how much
// payload the next record may carry. The idle reset is second-granular.
func (w *v6ShapedWriter) payloadLimitFor(now time.Time) int {
	nowUnix := now.Unix()
	if w.lastWriteUnix == 0 || nowUnix-w.lastWriteUnix > int64(w.profile.idleResetSec) {
		w.chunkSize = w.profile.chunkInitial
	}
	if w.chunkSize == 0 {
		w.chunkSize = w.profile.chunkInitial
	}
	payloadLimit := w.profile.chunkPayloadLimit(w.seq, w.chunkSize)
	if w.seq == 0 {
		payloadLimit = minInt(payloadLimit, w.profile.firstRecordCap)
	}
	w.chunkSize = w.profile.nextChunkSize(w.chunkSize)
	w.lastWriteUnix = nowUnix
	return maxInt(1, minInt(payloadLimit, v6MaxPayload))
}

// appendRecord builds one shaped record for payload and appends it to out.
func (w *v6ShapedWriter) appendRecord(out []byte, payload []byte) []byte {
	prefixLength := w.profile.recordPrefixLen(w.seq)
	saltBlockLength := 0
	saltPrefixLength := 0
	if !w.saltSent {
		saltBlockLength = w.profile.saltBlockLen
		saltPrefixLength = saltBlockLength - v6SaltSize
	}
	paddingLength := w.profile.paddingLen(w.seq, len(payload), prefixLength, saltPrefixLength, saltBlockLength)
	payloadCipherLength := 0
	if len(payload) > 0 {
		payloadCipherLength = len(payload) + v6TagSize
	}

	start := len(out)
	out = append(out, make([]byte, saltBlockLength+prefixLength+v6HeaderCipherSize+paddingLength+payloadCipherLength)...)
	record := out[start:]

	if saltBlockLength > 0 {
		block := record[:saltBlockLength]
		// the salt block is shaped padding generated for the sentinel sequence 0xffffffff
		// with the salt bytes scattered over it
		w.profile.fillPadding(0xffffffff, block)
		w.profile.writeSaltBlock(w.salt, block)
		w.saltSent = true
	}
	offset := saltBlockLength
	prefix := record[offset : offset+prefixLength]
	w.profile.fillPadding(w.seq, prefix)
	offset += prefixLength

	header := record[offset : offset+v6HeaderCipherSize]
	v6PutHeader(header, paddingLength, len(payload))
	w.aead.Seal(header[:0], w.nonce[:], header[:v6HeaderPlainSize], prefix)
	incrementV4Nonce(w.nonce[:])
	offset += v6HeaderCipherSize

	padding := record[offset : offset+paddingLength]
	w.profile.fillPadding(w.seq, padding)
	offset += paddingLength

	if len(payload) > 0 {
		region := record[offset : offset+payloadCipherLength]
		copy(region, payload)
		w.aead.Seal(region[:0], w.nonce[:], region[:len(payload)], padding)
		incrementV4Nonce(w.nonce[:])
		w.profile.mixPaddingPayload(w.seq, padding, region)
	}
	w.seq++
	return out
}

func (w *v6ShapedWriter) write(p []byte) error {
	now := time.Now()
	var out []byte
	for len(p) > 0 {
		n := minInt(len(p), w.payloadLimitFor(now))
		out = w.appendRecord(out, p[:n])
		p = p[n:]
	}
	_, err := w.Writer.Write(out)
	return err
}

func (w *v6ShapedWriter) writePacket(p []byte) error {
	// packet mode still advances the chunk schedule but emits the whole
	// datagram as a single record regardless of the current limit
	w.payloadLimitFor(time.Now())
	_, err := w.Writer.Write(w.appendRecord(nil, p))
	return err
}

func (w *v6ShapedWriter) writeZeroChunk() error {
	w.payloadLimitFor(time.Now())
	_, err := w.Writer.Write(w.appendRecord(nil, nil))
	return err
}

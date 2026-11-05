package snellv6

import (
	"crypto/cipher"
	"encoding/binary"
	"github.com/metacubex/sing/common"
	"io"
	"sync"
	"time"

	snell "github.com/metacubex/mihomo/transport/singsnell"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	N "github.com/metacubex/sing/common/network"
)

type shapedWriter struct {
	upstream      io.Writer
	profile       *Profile
	cipher        cipher.AEAD
	salt          []byte
	nonce         []byte
	seq           uint32
	saltSent      bool
	chunkSize     int
	lastWriteUnix int64
	access        sync.Mutex
}

func newShapedWriter(upstream io.Writer, profile *Profile, salt []byte, aead cipher.AEAD, nonce []byte) *shapedWriter {
	return &shapedWriter{upstream: upstream, profile: profile, cipher: aead, salt: salt, nonce: nonce}
}

func (w *shapedWriter) makeSliceRecord(payload []byte) *buf.Buffer {
	prefixLen := w.profile.recordPrefixLen(w.seq)
	saltBlockLen := 0
	saltPrefixLen := 0
	if !w.saltSent {
		saltBlockLen = w.profile.saltBlockLen
		saltPrefixLen = saltBlockLen - saltLen
	}
	paddingLen := w.profile.paddingLen(w.seq, len(payload), prefixLen, saltPrefixLen, saltBlockLen)
	payloadCipherLen := 0
	if len(payload) > 0 {
		payloadCipherLen = len(payload) + snell.AEADTagLen
	}
	out := buf.NewSize(saltBlockLen + prefixLen + snell.HeaderCipherLen + paddingLen + payloadCipherLen)

	if saltBlockLen > 0 {
		block := out.Extend(saltBlockLen)
		// Surge 6.7.0 (11520): FUN_100014610: fills the salt block with shaped padding
		// at sentinel sequence 0xffffffff before overwriting the salt positions.
		w.profile.fillPadding(0xffffffff, block)
		w.profile.writeSaltBlock(w.salt, block)
		w.saltSent = true
	}
	prefix := out.Extend(prefixLen)
	w.profile.fillPadding(w.seq, prefix)

	header := out.Extend(snell.HeaderCipherLen)
	putHeader(header, paddingLen, len(payload))
	w.cipher.Seal(header[:0], w.nonce, header[:snell.HeaderPlainLen], prefix)
	snell.IncreaseNonce(w.nonce)

	padding := out.Extend(paddingLen)
	w.profile.fillPadding(w.seq, padding)
	if len(payload) > 0 {
		region := out.Extend(payloadCipherLen)
		copy(region, payload)
		w.cipher.Seal(region[:0], w.nonce, region[:len(payload)], padding)
		snell.IncreaseNonce(w.nonce)
		w.profile.mixPaddingPayload(w.seq, padding, region)
	}
	w.seq++
	return out
}

func (w *shapedWriter) makeBufferRecord(buffer *buf.Buffer) *buf.Buffer {
	dataLen := buffer.Len()
	prefixLen := w.profile.recordPrefixLen(w.seq)
	saltBlockLen := 0
	saltPrefixLen := 0
	if !w.saltSent {
		saltBlockLen = w.profile.saltBlockLen
		saltPrefixLen = saltBlockLen - saltLen
	}
	paddingLen := w.profile.paddingLen(w.seq, dataLen, prefixLen, saltPrefixLen, saltBlockLen)
	frontLen := saltBlockLen + prefixLen + snell.HeaderCipherLen + paddingLen
	front := buffer.ExtendHeader(frontLen)
	if saltBlockLen > 0 {
		block := front[:saltBlockLen]
		// Surge 6.7.0 (11520): FUN_100014610: fills the salt block with shaped padding
		// at sentinel sequence 0xffffffff before overwriting the salt positions.
		w.profile.fillPadding(0xffffffff, block)
		w.profile.writeSaltBlock(w.salt, block)
		w.saltSent = true
	}
	prefix := front[saltBlockLen : saltBlockLen+prefixLen]
	w.profile.fillPadding(w.seq, prefix)

	header := front[saltBlockLen+prefixLen : saltBlockLen+prefixLen+snell.HeaderCipherLen]
	putHeader(header, paddingLen, dataLen)
	w.cipher.Seal(header[:0], w.nonce, header[:snell.HeaderPlainLen], prefix)
	snell.IncreaseNonce(w.nonce)

	padding := front[saltBlockLen+prefixLen+snell.HeaderCipherLen:]
	w.profile.fillPadding(w.seq, padding)
	if dataLen > 0 {
		region := buffer.From(frontLen)
		buffer.Extend(snell.AEADTagLen)
		w.cipher.Seal(region[:0], w.nonce, region[:dataLen], padding)
		snell.IncreaseNonce(w.nonce)
		region = buffer.From(frontLen)
		w.profile.mixPaddingPayload(w.seq, padding, region)
	}
	w.seq++
	return buffer
}

func (w *shapedWriter) writeRecords(records []*buf.Buffer) error {
	if len(records) == 1 {
		_, err := w.upstream.Write(records[0].Bytes())
		return err
	}
	out := buf.NewSize(buf.LenMulti(records))
	defer out.Release()
	for _, record := range records {
		copy(out.Extend(record.Len()), record.Bytes())
	}
	_, err := w.upstream.Write(out.Bytes())
	return err
}

func (w *shapedWriter) payloadLimitFor(now time.Time) int {
	nowUnix := now.Unix()
	// Surge 6.7.0 (11520): FUN_1000142d4/FUN_100014610: v6 writer idle reset is second-granular.
	if w.lastWriteUnix == 0 || nowUnix-w.lastWriteUnix > int64(w.profile.idleResetSec) {
		w.chunkSize = w.profile.chunkInitial
	}
	if w.chunkSize == 0 {
		w.chunkSize = w.profile.chunkInitial
	}
	payloadLimit := w.profile.chunkPayloadLimit(w.seq, w.chunkSize)
	if w.seq == 0 {
		payloadLimit = common.Min(payloadLimit, w.profile.firstRecordCap)
	}
	w.chunkSize = w.profile.nextChunkSize(w.chunkSize)
	w.lastWriteUnix = nowUnix
	return common.Max(1, common.Min(payloadLimit, maxPayload))
}

func (w *shapedWriter) Write(p []byte) (n int, err error) {
	w.access.Lock()
	defer w.access.Unlock()
	now := time.Now()
	originalLen := len(p)
	var records []*buf.Buffer
	defer func() {
		buf.ReleaseMulti(records)
	}()
	for len(p) > 0 {
		payloadLimit := w.payloadLimitFor(now)
		recordLen := common.Min(len(p), payloadLimit)
		records = append(records, w.makeSliceRecord(p[:recordLen]))
		p = p[recordLen:]
	}
	if len(records) == 0 {
		return 0, nil
	}
	err = w.writeRecords(records)
	if err != nil {
		return 0, err
	}
	n = originalLen
	return
}

func (w *shapedWriter) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	dataLen := buffer.Len()
	if dataLen == 0 {
		return nil
	}
	w.access.Lock()
	defer w.access.Unlock()
	now := time.Now()
	payloadLimit := w.payloadLimitFor(now)
	if dataLen <= payloadLimit {
		w.makeBufferRecord(buffer)
		_, err := w.upstream.Write(buffer.Bytes())
		return err
	}
	var records []*buf.Buffer
	defer func() {
		buf.ReleaseMulti(records)
	}()
	for data := buffer.Bytes(); len(data) > 0; {
		recordLen := common.Min(len(data), payloadLimit)
		records = append(records, w.makeSliceRecord(data[:recordLen]))
		data = data[recordLen:]
		if len(data) > 0 {
			payloadLimit = w.payloadLimitFor(now)
		}
	}
	return w.writeRecords(records)
}

func (w *shapedWriter) WritePacketBuffer(buffer *buf.Buffer) error {
	dataLen := buffer.Len()
	if dataLen == 0 {
		buffer.Release()
		return nil
	}
	if dataLen > maxPayload {
		buffer.Release()
		return snell.ErrPayloadTooLarge
	}
	w.access.Lock()
	defer w.access.Unlock()
	// snell-server v6.0.0rc: UDP packet mode still advances the dynamic chunk
	// state, but emits each complete datagram as one record regardless of the
	// current stream chunk limit.
	w.payloadLimitFor(time.Now())
	record := w.makeBufferRecord(buffer)
	_, err := w.upstream.Write(record.Bytes())
	record.Release()
	return err
}

func (w *shapedWriter) WriteZeroChunk() error {
	w.access.Lock()
	defer w.access.Unlock()
	w.payloadLimitFor(time.Now())
	record := w.makeSliceRecord(nil)
	defer record.Release()
	_, err := w.upstream.Write(record.Bytes())
	return err
}

func (w *shapedWriter) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	upstreamWriter, created := bufio.CreateVectorisedWriter(w.upstream)
	if !created {
		return nil, false
	}
	return w.CreateVectorisedWriterFor(upstreamWriter), true
}

func (w *shapedWriter) CreateVectorisedWriterFor(upstream N.VectorisedWriter) N.VectorisedWriter {
	return &vectorisedShapedWriter{writer: w, upstream: upstream}
}

type vectorisedShapedWriter struct {
	writer   *shapedWriter
	upstream N.VectorisedWriter
}

func (w *vectorisedShapedWriter) WriteVectorised(buffers []*buf.Buffer) error {
	var records []*buf.Buffer
	defer func() {
		buf.ReleaseMulti(records)
	}()
	recordWriter := w.writer
	recordWriter.access.Lock()
	defer recordWriter.access.Unlock()
	for _, buffer := range buffers {
		dataLen := buffer.Len()
		if dataLen == 0 {
			buffer.Release()
			continue
		}
		for data := buffer.Bytes(); len(data) > 0; {
			payloadLimit := recordWriter.payloadLimitFor(time.Now())
			recordLen := common.Min(len(data), payloadLimit)
			if len(data) == dataLen && dataLen <= payloadLimit {
				record := recordWriter.makeBufferRecord(buffer)
				buffer = nil
				records = append(records, record)
				break
			}
			records = append(records, recordWriter.makeSliceRecord(data[:recordLen]))
			data = data[recordLen:]
		}
		if buffer != nil {
			buffer.Release()
		}
	}
	if len(records) == 0 {
		return nil
	}
	flushRecords := records
	records = nil
	return w.upstream.WriteVectorised(flushRecords)
}

var _ N.VectorisedWriter = (*vectorisedShapedWriter)(nil)

func (w *shapedWriter) CreatePacketVectorisedWriterFor(upstream N.VectorisedWriter) N.VectorisedWriter {
	return &packetVectorisedShapedWriter{writer: w, upstream: upstream}
}

type packetVectorisedShapedWriter struct {
	writer   *shapedWriter
	upstream N.VectorisedWriter
}

func (w *packetVectorisedShapedWriter) WriteVectorised(buffers []*buf.Buffer) error {
	err := validatePacketVectorBuffers(buffers)
	if err != nil {
		return err
	}
	var records []*buf.Buffer
	defer func() {
		buf.ReleaseMulti(records)
	}()
	recordWriter := w.writer
	recordWriter.access.Lock()
	defer recordWriter.access.Unlock()
	for _, buffer := range buffers {
		if buffer.IsEmpty() {
			buffer.Release()
			continue
		}
		recordWriter.payloadLimitFor(time.Now())
		record := recordWriter.makeBufferRecord(buffer)
		records = append(records, record)
	}
	if len(records) == 0 {
		return nil
	}
	flushRecords := records
	records = nil
	return w.upstream.WriteVectorised(flushRecords)
}

var _ N.VectorisedWriter = (*packetVectorisedShapedWriter)(nil)

func (w *shapedWriter) FrontHeadroom() int {
	headroom := w.profile.recordPrefixMax + snell.HeaderCipherLen + w.profile.padMaxHeadroom
	if !w.saltSent {
		headroom += w.profile.saltBlockLen
	}
	return headroom
}

func (w *shapedWriter) RearHeadroom() int {
	return snell.AEADTagLen
}

func (w *shapedWriter) WriterMTU() int {
	return w.profile.chunkMax
}

func (w *shapedWriter) Upstream() any {
	return w.upstream
}

type shapedReader struct {
	baseReader
	psk     []byte
	profile *Profile
	cipher  cipher.AEAD
	nonce   []byte
	seq     uint32
}

func newShapedReader(upstream io.Reader, psk []byte, profile *Profile) *shapedReader {
	r := &shapedReader{psk: psk, profile: profile, nonce: make([]byte, snell.NonceLen)}
	r.upstream = upstream
	r.readFunc = r.read
	return r
}

func (r *shapedReader) read() (*buf.Buffer, error) {
	if r.cipher == nil {
		block := make([]byte, r.profile.saltBlockLen)
		_, err := io.ReadFull(r.upstream, block)
		if err != nil {
			return nil, err
		}
		salt := r.profile.extractSalt(block)
		aead, err := snell.NewAEAD(snell.DeriveKey(r.psk, salt[:]))
		if err != nil {
			return nil, err
		}
		r.cipher = aead
	}

	prefixLen := r.profile.recordPrefixLen(r.seq)
	head := buf.NewSize(prefixLen + snell.HeaderCipherLen)
	_, err := head.ReadFullFrom(r.upstream, prefixLen+snell.HeaderCipherLen)
	if err != nil {
		head.Release()
		return nil, err
	}
	prefix := head.To(prefixLen)
	headerCipher := head.Range(prefixLen, prefixLen+snell.HeaderCipherLen)
	_, err = r.cipher.Open(headerCipher[:0], r.nonce, headerCipher, prefix)
	if err != nil {
		head.Release()
		return nil, E.Cause(err, "open shaped header")
	}
	snell.IncreaseNonce(r.nonce)
	if headerCipher[0] != snell.HeaderVersion {
		head.Release()
		return nil, E.Extend(snell.ErrBadVersion, headerCipher[0])
	}
	// Surge 6.7.0 (11520): FUN_100013abc: default-shaped reader ignores the two reserved header bytes.
	paddingLen := int(binary.BigEndian.Uint16(headerCipher[3:5]))
	payloadLen := int(binary.BigEndian.Uint16(headerCipher[5:7]))
	head.Release()
	seq := r.seq
	r.seq++

	if payloadLen == 0 {
		if paddingLen > 0 {
			discard := buf.NewSize(paddingLen)
			_, err = discard.ReadFullFrom(r.upstream, paddingLen)
			discard.Release()
			if err != nil {
				return nil, err
			}
		}
		return nil, io.EOF
	}

	var padding *buf.Buffer
	if paddingLen > 0 {
		padding = buf.NewSize(paddingLen)
		_, err = padding.ReadFullFrom(r.upstream, paddingLen)
		if err != nil {
			padding.Release()
			return nil, err
		}
	}
	body := snell.NewBufferSize(r.readWaitOptions, payloadLen+snell.AEADTagLen)
	_, err = body.ReadFullFrom(r.upstream, payloadLen+snell.AEADTagLen)
	if err != nil {
		if padding != nil {
			padding.Release()
		}
		body.Release()
		return nil, err
	}
	var paddingBytes []byte
	if padding != nil {
		paddingBytes = padding.Bytes()
	}
	payloadCipher := body.Bytes()
	r.profile.mixPaddingPayload(seq, paddingBytes, payloadCipher)
	_, err = r.cipher.Open(payloadCipher[:0], r.nonce, payloadCipher, paddingBytes)
	if padding != nil {
		padding.Release()
	}
	if err != nil {
		body.Release()
		return nil, E.Cause(err, "open shaped payload")
	}
	snell.IncreaseNonce(r.nonce)
	body.Truncate(payloadLen)
	r.readWaitOptions.PostReturn(body)
	return body, nil
}

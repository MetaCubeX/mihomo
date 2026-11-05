package snellv6

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync"

	snell "github.com/metacubex/mihomo/transport/singsnell"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	N "github.com/metacubex/sing/common/network"
)

// Surge 6.7.0 (11520): FUN_100015c54/FUN_1000156e0: non-default records require zero padding length.
var errRecordPadding = E.New("snell: unexpected padding in non-default record")

func parseHeader(header []byte) (paddingLen int, payloadLen int, err error) {
	if header[0] != snell.HeaderVersion {
		return 0, 0, E.Extend(snell.ErrBadVersion, header[0])
	}
	if header[1] != 0 || header[2] != 0 {
		return 0, 0, snell.ErrReservedNonZero
	}
	return int(binary.BigEndian.Uint16(header[3:5])), int(binary.BigEndian.Uint16(header[5:7])), nil
}

func putHeader(header []byte, paddingLen int, payloadLen int) {
	header[0] = snell.HeaderVersion
	header[1] = 0
	header[2] = 0
	binary.BigEndian.PutUint16(header[3:5], uint16(paddingLen))
	binary.BigEndian.PutUint16(header[5:7], uint16(payloadLen))
}

type baseReader struct {
	upstream        io.Reader
	readFunc        func() (*buf.Buffer, error)
	cache           *buf.Buffer
	readWaitOptions N.ReadWaitOptions
}

func (r *baseReader) ReadRecord() (*buf.Buffer, error) {
	return r.readFunc()
}

func (r *baseReader) NextRecord() (*buf.Buffer, error) {
	record := r.cache
	if record != nil {
		r.cache = nil
		if record.IsEmpty() {
			record.Release()
		} else {
			return record, nil
		}
	}
	return r.ReadRecord()
}

func (r *baseReader) SetCache(cache *buf.Buffer) {
	r.cache = cache
}

func (r *baseReader) ReleaseCache() {
	if r.cache != nil {
		r.cache.Release()
		r.cache = nil
	}
}

func (r *baseReader) Read(p []byte) (n int, err error) {
	for {
		if r.cache != nil {
			if r.cache.IsEmpty() {
				r.cache.Release()
				r.cache = nil
			} else {
				n = copy(p, r.cache.Bytes())
				r.cache.Advance(n)
				return
			}
		}
		r.cache, err = r.ReadRecord()
		if err != nil {
			return
		}
	}
}

func (r *baseReader) ReadBuffer(buffer *buf.Buffer) error {
	for {
		if r.cache != nil {
			if r.cache.IsEmpty() {
				r.cache.Release()
				r.cache = nil
			} else {
				n, _ := buffer.Write(r.cache.Bytes())
				r.cache.Advance(n)
				return nil
			}
		}
		var err error
		r.cache, err = r.ReadRecord()
		if err != nil {
			return err
		}
	}
}

func (r *baseReader) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	r.readWaitOptions = options
	return false
}

func (r *baseReader) WaitReadBuffer() (buffer *buf.Buffer, err error) {
	for {
		if r.cache == nil {
			return r.ReadRecord()
		}
		buffer = r.cache
		r.cache = nil
		if buffer.IsEmpty() {
			buffer.Release()
			continue
		}
		if buffer.Start() >= r.readWaitOptions.FrontHeadroom && buffer.FreeLen() >= r.readWaitOptions.RearHeadroom {
			return
		}
		buffer = r.readWaitOptions.Copy(buffer)
		return buffer, nil
	}
}

func (r *baseReader) Upstream() any {
	return r.upstream
}

type unshapedReader struct {
	baseReader
	cipher cipher.AEAD
	nonce  []byte
}

func newUnshapedReader(upstream io.Reader, aead cipher.AEAD, nonce []byte) *unshapedReader {
	r := &unshapedReader{cipher: aead, nonce: nonce}
	r.upstream = upstream
	r.readFunc = r.read
	return r
}

func (r *unshapedReader) read() (*buf.Buffer, error) {
	headerCipher := buf.NewSize(snell.HeaderCipherLen)
	_, err := headerCipher.ReadFullFrom(r.upstream, snell.HeaderCipherLen)
	if err != nil {
		headerCipher.Release()
		return nil, err
	}
	_, err = r.cipher.Open(headerCipher.Index(0), r.nonce, headerCipher.Bytes(), nil)
	if err != nil {
		headerCipher.Release()
		return nil, E.Cause(err, "open record header")
	}
	snell.IncreaseNonce(r.nonce)
	paddingLen, payloadLen, err := parseHeader(headerCipher.To(snell.HeaderPlainLen))
	headerCipher.Release()
	if err != nil {
		return nil, err
	}
	if paddingLen != 0 {
		return nil, errRecordPadding
	}
	if payloadLen == 0 {
		return nil, io.EOF
	}
	body := snell.NewBufferSize(r.readWaitOptions, payloadLen+snell.AEADTagLen)
	_, err = body.ReadFullFrom(r.upstream, payloadLen+snell.AEADTagLen)
	if err != nil {
		body.Release()
		return nil, err
	}
	_, err = r.cipher.Open(body.Index(0), r.nonce, body.Bytes(), nil)
	if err != nil {
		body.Release()
		return nil, E.Cause(err, "open record payload")
	}
	snell.IncreaseNonce(r.nonce)
	body.Truncate(payloadLen)
	r.readWaitOptions.PostReturn(body)
	return body, nil
}

type unshapedWriter struct {
	upstream io.Writer
	cipher   cipher.AEAD
	nonce    []byte
	access   sync.Mutex
}

func newUnshapedWriter(upstream io.Writer, aead cipher.AEAD, nonce []byte) *unshapedWriter {
	return &unshapedWriter{upstream: upstream, cipher: aead, nonce: nonce}
}

func (w *unshapedWriter) sealHeader(header []byte, payloadLen int) {
	putHeader(header, 0, payloadLen)
	w.cipher.Seal(header[:0], w.nonce, header[:snell.HeaderPlainLen], nil)
	snell.IncreaseNonce(w.nonce)
}

func (w *unshapedWriter) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		var data []byte
		if len(p) > maxPayload {
			data = p[:maxPayload]
			p = p[maxPayload:]
		} else {
			data = p
			p = nil
		}
		buffer := buf.NewSize(snell.HeaderCipherLen + len(data) + snell.AEADTagLen)
		w.access.Lock()
		w.sealHeader(buffer.Extend(snell.HeaderCipherLen), len(data))
		buffer.Write(data)
		w.cipher.Seal(buffer.From(snell.HeaderCipherLen)[:0], w.nonce, buffer.From(snell.HeaderCipherLen), nil)
		buffer.Extend(snell.AEADTagLen)
		snell.IncreaseNonce(w.nonce)
		_, err = w.upstream.Write(buffer.Bytes())
		w.access.Unlock()
		buffer.Release()
		if err != nil {
			return
		}
		n += len(data)
	}
	return
}

func (w *unshapedWriter) makeSliceRecordLocked(payload []byte) *buf.Buffer {
	record := buf.NewSize(snell.HeaderCipherLen + len(payload) + snell.AEADTagLen)
	w.sealHeader(record.Extend(snell.HeaderCipherLen), len(payload))
	common.Must1(record.Write(payload))
	w.cipher.Seal(record.From(snell.HeaderCipherLen)[:0], w.nonce, record.From(snell.HeaderCipherLen), nil)
	record.Extend(snell.AEADTagLen)
	snell.IncreaseNonce(w.nonce)
	return record
}

func (w *unshapedWriter) makeBufferRecordLocked(buffer *buf.Buffer) *buf.Buffer {
	dataLen := buffer.Len()
	header := buffer.ExtendHeader(snell.HeaderCipherLen)
	w.sealHeader(header, dataLen)
	payloadCipher := buffer.From(snell.HeaderCipherLen)
	buffer.Extend(snell.AEADTagLen)
	w.cipher.Seal(payloadCipher[:0], w.nonce, payloadCipher[:dataLen], nil)
	snell.IncreaseNonce(w.nonce)
	return buffer
}

func (w *unshapedWriter) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	dataLen := buffer.Len()
	if dataLen == 0 {
		return nil
	}
	if dataLen > maxPayload {
		return common.Error(w.Write(buffer.Bytes()))
	}
	w.access.Lock()
	defer w.access.Unlock()
	w.makeBufferRecordLocked(buffer)
	return common.Error(w.upstream.Write(buffer.Bytes()))
}

func (w *unshapedWriter) WritePacketBuffer(buffer *buf.Buffer) error {
	if buffer.Len() > maxPayload {
		buffer.Release()
		return snell.ErrPayloadTooLarge
	}
	return w.WriteBuffer(buffer)
}

func (w *unshapedWriter) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	upstreamWriter, created := bufio.CreateVectorisedWriter(w.upstream)
	if !created {
		return nil, false
	}
	return w.CreateVectorisedWriterFor(upstreamWriter), true
}

func (w *unshapedWriter) CreateVectorisedWriterFor(upstream N.VectorisedWriter) N.VectorisedWriter {
	return &vectorisedUnshapedWriter{writer: w, upstream: upstream}
}

type vectorisedUnshapedWriter struct {
	writer   *unshapedWriter
	upstream N.VectorisedWriter
}

func (w *vectorisedUnshapedWriter) WriteVectorised(buffers []*buf.Buffer) error {
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
			if len(data) == dataLen && dataLen <= maxPayload {
				record := recordWriter.makeBufferRecordLocked(buffer)
				buffer = nil
				records = append(records, record)
				break
			}
			recordLen := common.Min(len(data), maxPayload)
			records = append(records, recordWriter.makeSliceRecordLocked(data[:recordLen]))
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

func (w *unshapedWriter) CreatePacketVectorisedWriterFor(upstream N.VectorisedWriter) N.VectorisedWriter {
	return &packetVectorisedUnshapedWriter{writer: w, upstream: upstream}
}

type packetVectorisedUnshapedWriter struct {
	writer   *unshapedWriter
	upstream N.VectorisedWriter
}

func validatePacketVectorBuffers(buffers []*buf.Buffer) error {
	for _, buffer := range buffers {
		if buffer.Len() > maxPayload {
			buf.ReleaseMulti(buffers)
			return snell.ErrPayloadTooLarge
		}
	}
	return nil
}

func (w *packetVectorisedUnshapedWriter) WriteVectorised(buffers []*buf.Buffer) error {
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
		record := recordWriter.makeBufferRecordLocked(buffer)
		records = append(records, record)
	}
	if len(records) == 0 {
		return nil
	}
	flushRecords := records
	records = nil
	return w.upstream.WriteVectorised(flushRecords)
}

func (w *unshapedWriter) WriteZeroChunk() error {
	buffer := buf.NewSize(snell.HeaderCipherLen)
	w.access.Lock()
	defer w.access.Unlock()
	w.sealHeader(buffer.Extend(snell.HeaderCipherLen), 0)
	err := common.Error(w.upstream.Write(buffer.Bytes()))
	buffer.Release()
	return err
}

func (w *unshapedWriter) FrontHeadroom() int {
	return snell.HeaderCipherLen
}

func (w *unshapedWriter) RearHeadroom() int {
	return snell.AEADTagLen
}

func (w *unshapedWriter) WriterMTU() int {
	return maxPayload
}

func (w *unshapedWriter) Upstream() any {
	return w.upstream
}

type rawReader struct {
	baseReader
}

func newRawReader(upstream io.Reader) *rawReader {
	r := &rawReader{}
	r.upstream = upstream
	r.readFunc = r.read
	return r
}

func (r *rawReader) read() (*buf.Buffer, error) {
	header := buf.NewSize(snell.HeaderPlainLen)
	_, err := header.ReadFullFrom(r.upstream, snell.HeaderPlainLen)
	if err != nil {
		header.Release()
		return nil, err
	}
	paddingLen, payloadLen, err := parseHeader(header.Bytes())
	header.Release()
	if err != nil {
		return nil, err
	}
	if paddingLen != 0 {
		return nil, errRecordPadding
	}
	if payloadLen == 0 {
		return nil, io.EOF
	}
	body := snell.NewBufferSize(r.readWaitOptions, payloadLen)
	_, err = body.ReadFullFrom(r.upstream, payloadLen)
	if err != nil {
		body.Release()
		return nil, err
	}
	r.readWaitOptions.PostReturn(body)
	return body, nil
}

type rawWriter struct {
	upstream io.Writer
	access   sync.Mutex
}

func newRawWriter(upstream io.Writer) *rawWriter {
	return &rawWriter{upstream: upstream}
}

func (w *rawWriter) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		var data []byte
		if len(p) > maxPayload {
			data = p[:maxPayload]
			p = p[maxPayload:]
		} else {
			data = p
			p = nil
		}
		buffer := buf.NewSize(snell.HeaderPlainLen + len(data))
		putHeader(buffer.Extend(snell.HeaderPlainLen), 0, len(data))
		buffer.Write(data)
		w.access.Lock()
		_, err = w.upstream.Write(buffer.Bytes())
		w.access.Unlock()
		buffer.Release()
		if err != nil {
			return
		}
		n += len(data)
	}
	return
}

func (w *rawWriter) makeSliceRecordLocked(payload []byte) *buf.Buffer {
	record := buf.NewSize(snell.HeaderPlainLen + len(payload))
	putHeader(record.Extend(snell.HeaderPlainLen), 0, len(payload))
	common.Must1(record.Write(payload))
	return record
}

func (w *rawWriter) makeBufferRecordLocked(buffer *buf.Buffer) *buf.Buffer {
	dataLen := buffer.Len()
	putHeader(buffer.ExtendHeader(snell.HeaderPlainLen), 0, dataLen)
	return buffer
}

func (w *rawWriter) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	dataLen := buffer.Len()
	if dataLen == 0 {
		return nil
	}
	if dataLen > maxPayload {
		return common.Error(w.Write(buffer.Bytes()))
	}
	w.access.Lock()
	defer w.access.Unlock()
	w.makeBufferRecordLocked(buffer)
	return common.Error(w.upstream.Write(buffer.Bytes()))
}

func (w *rawWriter) WritePacketBuffer(buffer *buf.Buffer) error {
	if buffer.Len() > maxPayload {
		buffer.Release()
		return snell.ErrPayloadTooLarge
	}
	return w.WriteBuffer(buffer)
}

func (w *rawWriter) CreateVectorisedWriter() (N.VectorisedWriter, bool) {
	upstreamWriter, created := bufio.CreateVectorisedWriter(w.upstream)
	if !created {
		return nil, false
	}
	return w.CreateVectorisedWriterFor(upstreamWriter), true
}

func (w *rawWriter) CreateVectorisedWriterFor(upstream N.VectorisedWriter) N.VectorisedWriter {
	return &vectorisedRawWriter{writer: w, upstream: upstream}
}

type vectorisedRawWriter struct {
	writer   *rawWriter
	upstream N.VectorisedWriter
}

func (w *vectorisedRawWriter) WriteVectorised(buffers []*buf.Buffer) error {
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
			if len(data) == dataLen && dataLen <= maxPayload {
				record := recordWriter.makeBufferRecordLocked(buffer)
				buffer = nil
				records = append(records, record)
				break
			}
			recordLen := common.Min(len(data), maxPayload)
			records = append(records, recordWriter.makeSliceRecordLocked(data[:recordLen]))
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

func (w *rawWriter) CreatePacketVectorisedWriterFor(upstream N.VectorisedWriter) N.VectorisedWriter {
	return &packetVectorisedRawWriter{writer: w, upstream: upstream}
}

type packetVectorisedRawWriter struct {
	writer   *rawWriter
	upstream N.VectorisedWriter
}

func (w *packetVectorisedRawWriter) WriteVectorised(buffers []*buf.Buffer) error {
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
		record := recordWriter.makeBufferRecordLocked(buffer)
		records = append(records, record)
	}
	if len(records) == 0 {
		return nil
	}
	flushRecords := records
	records = nil
	return w.upstream.WriteVectorised(flushRecords)
}

func (w *rawWriter) WriteZeroChunk() error {
	buffer := buf.NewSize(snell.HeaderPlainLen)
	putHeader(buffer.Extend(snell.HeaderPlainLen), 0, 0)
	w.access.Lock()
	defer w.access.Unlock()
	err := common.Error(w.upstream.Write(buffer.Bytes()))
	buffer.Release()
	return err
}

func (w *rawWriter) FrontHeadroom() int {
	return snell.HeaderPlainLen
}

func (w *rawWriter) RearHeadroom() int {
	return 0
}

func (w *rawWriter) WriterMTU() int {
	return maxPayload
}

func (w *rawWriter) Upstream() any {
	return w.upstream
}

var (
	_ N.ExtendedReader             = (*unshapedReader)(nil)
	_ N.ReadWaiter                 = (*unshapedReader)(nil)
	_ N.ExtendedWriter             = (*unshapedWriter)(nil)
	_ snell.VectorisedWriteCreator = (*unshapedWriter)(nil)
	_ N.VectorisedWriter           = (*vectorisedUnshapedWriter)(nil)
	_ N.VectorisedWriter           = (*packetVectorisedUnshapedWriter)(nil)
	_ N.FrontHeadroom              = (*unshapedWriter)(nil)
	_ N.ExtendedReader             = (*rawReader)(nil)
	_ N.ReadWaiter                 = (*rawReader)(nil)
	_ N.ExtendedWriter             = (*rawWriter)(nil)
	_ snell.VectorisedWriteCreator = (*rawWriter)(nil)
	_ N.VectorisedWriter           = (*vectorisedRawWriter)(nil)
	_ N.VectorisedWriter           = (*packetVectorisedRawWriter)(nil)
	_ snell.VectorisedWriteCreator = (*shapedWriter)(nil)
	_ N.WriterWithMTU              = (*unshapedWriter)(nil)
	_ N.WriterWithMTU              = (*rawWriter)(nil)
	_ N.WriterWithMTU              = (*shapedWriter)(nil)
)

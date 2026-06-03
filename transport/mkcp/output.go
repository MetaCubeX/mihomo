package mkcp

import (
	"io"
	"sync"
	"time"
)

type SegmentWriter interface {
	Write(seg Segment) error
}

type SimpleSegmentWriter struct {
	sync.Mutex
	buffer *Buffer
	writer io.Writer
}

func NewSegmentWriter(writer io.Writer) SegmentWriter {
	return &SimpleSegmentWriter{
		writer: writer,
		buffer: New(),
	}
}

func (w *SimpleSegmentWriter) Write(seg Segment) error {
	w.Lock()
	defer w.Unlock()

	w.buffer.Clear()
	rawBytes := w.buffer.Extend(seg.ByteSize())
	seg.Serialize(rawBytes)
	_, err := w.writer.Write(w.buffer.Bytes())
	return err
}

// RetryableWriter retries a failed segment write a few times before giving up,
// mirroring xray-core's retry.Timed(5, 100) wrapping of the UDP writer.
type RetryableWriter struct {
	writer SegmentWriter
}

func NewRetryableWriter(writer SegmentWriter) SegmentWriter {
	return &RetryableWriter{writer: writer}
}

func (w *RetryableWriter) Write(seg Segment) error {
	var err error
	for i := 0; i < 5; i++ {
		if err = w.writer.Write(seg); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

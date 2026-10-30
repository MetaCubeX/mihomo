package miu

import (
	"strconv"
	"strings"
	"sync/atomic"
)

// Frames travel inside outer TLS records: type(1) · len(u16 BE) · payload.
const (
	frPad            = 0 // padding, discarded
	frSettings       = 1 // C→S text
	frServerSettings = 2 // S→C text
	frUpdatePadding  = 3 // S→C padding scheme text
	frOpen           = 4 // C→S destination, as a SOCKS address
	frData           = 5 // payload, encrypted once by the outer TLS
	frRaw            = 6 // u32 BE = N: N bytes follow on TCP outside the outer TLS. Last frame of its record
	frEnd            = 7 // this direction is finished
	frReset          = 8 // C→S abort the stream: the uplink ends here, stop the downlink and send END

	frameHead = 3
	// maxData keeps one DATA frame, header included, inside a single TLS record.
	maxData = 16000
	// maxBatch is the largest batch of payload sent as one "packet" while a stream is in its DATA phase.
	maxBatch = 2 * maxData
	// maxSeg is the upper bound of one raw segment.
	maxSeg = 1 << 20
	// rawMin: in the raw phase a batch smaller than this still goes out as DATA. A RAW frame needs a record
	// (and usually a packet) of its own, which doubles the packet count for small writes.
	rawMin = 4096
	// sniffLimit is how far into a direction the inner TLS handshake is looked for before giving up.
	sniffLimit = 64 << 10
)

func appendFrame(b []byte, typ byte, payload []byte) []byte {
	b = append(b, typ, byte(len(payload)>>8), byte(len(payload)))
	return append(b, payload...)
}

// appendData encodes p as DATA frames of at most maxData bytes each.
func appendData(dst, p []byte) []byte {
	for len(p) > 0 {
		k := minInt(len(p), maxData)
		dst = appendFrame(dst, frData, p[:k])
		p = p[k:]
	}
	return dst
}

// minInt is the builtin min of Go 1.21.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseKV parses a settings text: newline separated key=value pairs.
func parseKV(text string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = v
		}
	}
	return m
}

func kvInt(m map[string]string, key string) (int64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	return n, err == nil
}

// testObserver is only set by tests, to assert which code path was taken.
var testObserver atomic.Pointer[func(event string)]

func observe(event string) {
	if f := testObserver.Load(); f != nil {
		(*f)(event)
	}
}

package route

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/log"
)

type failedLogWriter struct {
	header  http.Header
	payload string
	debug   bool
}

func (w *failedLogWriter) Header() http.Header { return w.header }
func (w *failedLogWriter) WriteHeader(int)     {}
func (w *failedLogWriter) Flush()              {}
func (w *failedLogWriter) Write(p []byte) (int, error) {
	w.payload = string(p)
	w.debug = log.DebugEnabled()
	return 0, errors.New("synthetic disconnect")
}

func TestLogAPIInterestCleanup(t *testing.T) {
	old := log.Level()
	log.SetLevel(log.ERROR)
	defer log.SetLevel(old)
	for _, format := range []string{"", "&format=structured"} {
		w := &failedLogWriter{header: make(http.Header)}
		done := make(chan struct{})
		go func() {
			defer close(done)
			getLogs(w, httptest.NewRequest("GET", "http://localhost/logs?level=debug"+format, nil))
		}()
		deadline := time.Now().Add(time.Second)
		for !log.DebugEnabled() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if !log.DebugEnabled() {
			t.Fatal("API did not declare DEBUG interest")
		}
		log.Debugln("interest-test")
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("write failure did not finish log handler")
		}
		if log.DebugEnabled() || !strings.Contains(w.payload, "interest-test") {
			t.Fatal("DEBUG interest or payload incorrect", w.payload)
		}
	}
	info := &failedLogWriter{header: make(http.Header)}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		getLogs(info, httptest.NewRequest("GET", "http://localhost/logs?level=info", nil))
	}()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
waiting:
	for {
		select {
		case <-finished:
			break waiting
		case <-tick.C:
			log.Infoln("info-interest-test")
		case <-timeout.C:
			t.Fatal("INFO handler did not observe write failure")
		}
	}
	if info.debug || !strings.Contains(info.payload, "info-interest-test") {
		t.Fatal("INFO API enabled DEBUG or lost INFO", info.payload)
	}
	invalid := httptest.NewRecorder()
	getLogs(invalid, httptest.NewRequest("GET", "http://localhost/logs?level=invalid", nil))
	if invalid.Code != http.StatusBadRequest || log.DebugEnabled() {
		t.Fatal("invalid request registered interest")
	}
	request := httptest.NewRequest("GET", "http://localhost/logs?level=debug", nil)
	request.Header.Set("Upgrade", "websocket")
	getLogs(httptest.NewRecorder(), request)
	if log.DebugEnabled() {
		t.Fatal("failed upgrade registered interest")
	}
}

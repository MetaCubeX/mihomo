package xhttp

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
)

func TestValidateRequest(t *testing.T) {
	cfg := &Config{
		Host: "example.com",
		Path: "/xhttp/",
	}
	handler := &requestHandler{
		config: cfg,
	}

	tests := []struct {
		name        string
		host        string
		path        string
		expectError bool
	}{
		{"valid host and path", "example.com", "/xhttp/test", false},
		{"empty host allowed", "", "/xhttp/test", false},
		{"wrong host", "wrong.com", "/xhttp/test", true},
		{"wrong path prefix", "example.com", "/other/test", true},
		{"valid with session", "example.com", "/xhttp/550e8400-e29b-41d4-a716-446655440000", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+tt.path, nil)
			req.Host = tt.host
			err := handler.validateRequest(req)
			if (err != nil) != tt.expectError {
				t.Errorf("validateRequest() error = %v, expectError %v", err, tt.expectError)
			}
		})
	}
}

func TestParseSessionID(t *testing.T) {
	handler := &requestHandler{
		config: &Config{Path: "/xhttp/"},
	}

	validUUID := uuid.Must(uuid.NewV4()).String()

	tests := []struct {
		name        string
		path        string
		expectError bool
		expectedID  string
	}{
		{"valid session ID", "/xhttp/" + validUUID, false, validUUID},
		{"valid with trailing", "/xhttp/" + validUUID + "/", false, validUUID},
		{"invalid UUID format", "/xhttp/not-a-uuid", true, ""},
		{"missing session ID", "/xhttp/", true, ""},
		{"wrong prefix", "/other/" + validUUID, true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessionID, err := handler.parseSessionID(tt.path)
			if (err != nil) != tt.expectError {
				t.Errorf("parseSessionID() error = %v, expectError %v", err, tt.expectError)
			}
			if !tt.expectError && sessionID != tt.expectedID {
				t.Errorf("parseSessionID() = %v, want %v", sessionID, tt.expectedID)
			}
		})
	}
}

func TestParseSeq(t *testing.T) {
	handler := &requestHandler{
		config: &Config{Path: "/xhttp/"},
	}

	sessionID := uuid.Must(uuid.NewV4()).String()

	tests := []struct {
		name        string
		path        string
		expectError bool
		expectedSeq uint64
	}{
		{"valid seq", "/xhttp/" + sessionID + "/123", false, 123},
		{"zero seq", "/xhttp/" + sessionID + "/0", false, 0},
		{"large seq", "/xhttp/" + sessionID + "/999999", false, 999999},
		{"missing seq", "/xhttp/" + sessionID, true, 0},
		{"invalid seq", "/xhttp/" + sessionID + "/abc", true, 0},
		{"negative seq", "/xhttp/" + sessionID + "/-1", true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seq, err := handler.parseSeq(tt.path)
			if (err != nil) != tt.expectError {
				t.Errorf("parseSeq() error = %v, expectError %v", err, tt.expectError)
			}
			if !tt.expectError && seq != tt.expectedSeq {
				t.Errorf("parseSeq() = %v, want %v", seq, tt.expectedSeq)
			}
		})
	}
}

func TestIsValidSessionID(t *testing.T) {
	validUUID := uuid.Must(uuid.NewV4()).String()

	tests := []struct {
		name  string
		id    string
		valid bool
	}{
		{"valid UUID v4", validUUID, true},
		{"invalid format", "not-a-uuid", false},
		{"empty string", "", false},
		{"partial UUID", "550e8400-e29b-41d4", false},
		{"UUID with extra chars", validUUID + "extra", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidSessionID(tt.id); got != tt.valid {
				t.Errorf("isValidSessionID() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestGetOrCreateSession(t *testing.T) {
	cfg := &Config{}
	cfg.normalize()
	handler := &requestHandler{
		config: cfg,
	}

	sessionID := uuid.Must(uuid.NewV4()).String()

	session1, err := handler.getOrCreateSession(sessionID)
	if err != nil {
		t.Fatalf("getOrCreateSession() failed: %v", err)
	}
	if session1 == nil {
		t.Fatal("Expected non-nil session")
	}
	if session1.sessionId != sessionID {
		t.Errorf("Session ID = %v, want %v", session1.sessionId, sessionID)
	}

	session2, err := handler.getOrCreateSession(sessionID)
	if err != nil {
		t.Fatalf("getOrCreateSession() second call failed: %v", err)
	}
	if session1 != session2 {
		t.Error("Expected same session instance for same ID")
	}

	otherSessionID := uuid.Must(uuid.NewV4()).String()
	session3, err := handler.getOrCreateSession(otherSessionID)
	if err != nil {
		t.Fatalf("getOrCreateSession() with different ID failed: %v", err)
	}
	if session1 == session3 {
		t.Error("Expected different session for different ID")
	}
}

func TestHandleStreamUpload(t *testing.T) {
	cfg := &Config{}
	cfg.normalize()
	handler := &requestHandler{
		config: cfg,
	}

	sessionID := uuid.Must(uuid.NewV4()).String()
	body := bytes.NewReader([]byte("test data"))
	req := httptest.NewRequest("POST", "/xhttp/"+sessionID, body)
	w := httptest.NewRecorder()

	handler.handleStreamUpload(w, req, sessionID)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusOK)
	}

	session, _ := handler.getOrCreateSession(sessionID)
	session.uploadQueue.Close()
}

func TestHandlePacketUpload(t *testing.T) {
	cfg := &Config{}
	cfg.normalize()
	handler := &requestHandler{
		config: cfg,
	}

	sessionID := uuid.Must(uuid.NewV4()).String()
	payload := []byte("packet data")
	req := httptest.NewRequest("POST", "/xhttp/"+sessionID+"/5", bytes.NewReader(payload))
	w := httptest.NewRecorder()

	handler.handlePacketUpload(w, req, sessionID, 5)

	if w.Code != http.StatusOK {
		t.Errorf("Status = %v, want %v", w.Code, http.StatusOK)
	}

	session, _ := handler.getOrCreateSession(sessionID)
	time.Sleep(10 * time.Millisecond)

	buf := make([]byte, 100)
	session.uploadQueue.Push(Packet{Payload: []byte("0"), Seq: 0})
	session.uploadQueue.Push(Packet{Payload: []byte("1"), Seq: 1})
	session.uploadQueue.Push(Packet{Payload: []byte("2"), Seq: 2})
	session.uploadQueue.Push(Packet{Payload: []byte("3"), Seq: 3})
	session.uploadQueue.Push(Packet{Payload: []byte("4"), Seq: 4})

	for i := 0; i < 6; i++ {
		n, err := session.uploadQueue.Read(buf)
		if err != nil {
			t.Fatalf("Read %d failed: %v", i, err)
		}
		if i < 5 {
			expected := string(rune('0' + i))
			if string(buf[:n]) != expected {
				t.Errorf("Read %d: got %s, want %s", i, string(buf[:n]), expected)
			}
		} else {
			if string(buf[:n]) != "packet data" {
				t.Errorf("Read 5: got %s, want packet data", string(buf[:n]))
			}
		}
	}

	session.uploadQueue.Close()
}

func TestApplyResponseHeaders(t *testing.T) {
	tests := []struct {
		name           string
		noGRPCHeader   bool
		noSSEHeader    bool
		customHeaders  map[string]string
		expectedType   string
		expectedCache  string
		expectedCustom string
	}{
		{
			name:         "default grpc",
			noGRPCHeader: false,
			noSSEHeader:  false,
			expectedType: "application/grpc",
		},
		{
			name:          "sse headers",
			noGRPCHeader:  true,
			noSSEHeader:   false,
			expectedType:  "text/event-stream",
			expectedCache: "no-cache",
		},
		{
			name:         "octet stream",
			noGRPCHeader: true,
			noSSEHeader:  true,
			expectedType: "application/octet-stream",
		},
		{
			name:           "with custom headers",
			customHeaders:  map[string]string{"X-Custom": "value"},
			expectedType:   "application/grpc",
			expectedCustom: "value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				NoGRPCHeader: tt.noGRPCHeader,
				NoSSEHeader:  tt.noSSEHeader,
				Headers:      tt.customHeaders,
			}
			handler := &requestHandler{config: cfg}
			w := httptest.NewRecorder()

			handler.applyResponseHeaders(w)

			if ct := w.Header().Get("Content-Type"); ct != tt.expectedType {
				t.Errorf("Content-Type = %v, want %v", ct, tt.expectedType)
			}
			if tt.expectedCache != "" {
				if cc := w.Header().Get("Cache-Control"); cc != tt.expectedCache {
					t.Errorf("Cache-Control = %v, want %v", cc, tt.expectedCache)
				}
			}
			if tt.expectedCustom != "" {
				if custom := w.Header().Get("X-Custom"); custom != tt.expectedCustom {
					t.Errorf("X-Custom = %v, want %v", custom, tt.expectedCustom)
				}
			}
		})
	}
}

func TestServeHTTP(t *testing.T) {
	cfg := &Config{
		Host: "example.com",
		Path: "/xhttp/",
	}
	cfg.normalize()
	handler := &requestHandler{
		config: cfg,
	}

	sessionID := uuid.Must(uuid.NewV4()).String()

	t.Run("invalid host", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://wrong.com/xhttp/"+sessionID, nil)
		req.Host = "wrong.com"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Status = %v, want %v", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("invalid session ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com/xhttp/invalid-uuid", nil)
		req.Host = "example.com"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Status = %v, want %v", w.Code, http.StatusNotFound)
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "http://example.com/xhttp/"+sessionID, nil)
		req.Host = "example.com"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Status = %v, want %v", w.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("POST stream upload", func(t *testing.T) {
		body := strings.NewReader("stream data")
		req := httptest.NewRequest("POST", "http://example.com/xhttp/"+sessionID, body)
		req.Host = "example.com"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %v, want %v", w.Code, http.StatusOK)
		}
	})

	t.Run("POST packet upload", func(t *testing.T) {
		body := bytes.NewReader([]byte("packet"))
		req := httptest.NewRequest("POST", "http://example.com/xhttp/"+sessionID+"/0", body)
		req.Host = "example.com"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %v, want %v", w.Code, http.StatusOK)
		}
	})

	session, _ := handler.getOrCreateSession(sessionID)
	session.uploadQueue.Close()
}

func TestHandleDownloadStream(t *testing.T) {
	cfg := &Config{}
	cfg.normalize()
	handler := &requestHandler{
		config: cfg,
	}

	sessionID := uuid.Must(uuid.NewV4()).String()

	session, _ := handler.getOrCreateSession(sessionID)
	go func() {
		time.Sleep(10 * time.Millisecond)
		session.downloadQueue <- []byte("data1")
		time.Sleep(10 * time.Millisecond)
		session.downloadQueue <- []byte("data2")
		time.Sleep(10 * time.Millisecond)
		close(session.downloadQueue)
	}()

	req := httptest.NewRequest("GET", "/xhttp/"+sessionID, nil)
	w := httptest.NewRecorder()

	handler.handleDownload(w, req, sessionID)

	body := w.Body.String()
	if !strings.Contains(body, "data1") {
		t.Error("Response should contain data1")
	}
	if !strings.Contains(body, "data2") {
		t.Error("Response should contain data2")
	}
}

func TestSessionCleanup(t *testing.T) {
	cfg := &Config{}
	cfg.normalize()
	handler := &requestHandler{
		config: cfg,
	}

	sessionID := uuid.Must(uuid.NewV4()).String()

	session, _ := handler.getOrCreateSession(sessionID)
	if _, exists := handler.sessions.Load(sessionID); !exists {
		t.Fatal("Session should exist after creation")
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		close(session.downloadQueue)
	}()

	req := httptest.NewRequest("GET", "/xhttp/"+sessionID, nil)
	w := httptest.NewRecorder()

	handler.handleDownload(w, req, sessionID)

	if _, exists := handler.sessions.Load(sessionID); exists {
		t.Error("Session should be deleted after handleDownload completes")
	}
}

func TestConcurrentSessionAccess(t *testing.T) {
	cfg := &Config{}
	cfg.normalize()
	handler := &requestHandler{
		config: cfg,
	}

	sessionID := uuid.Must(uuid.NewV4()).String()

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			session, _ := handler.getOrCreateSession(sessionID)
			if session == nil {
				t.Error("Expected non-nil session")
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	count := 0
	handler.sessions.Range(func(key, value interface{}) bool {
		count++
		return true
	})

	if count != 1 {
		t.Errorf("Expected 1 session, got %d", count)
	}
}

func TestMultiplePacketsOutOfOrder(t *testing.T) {
	cfg := &Config{}
	cfg.normalize()
	handler := &requestHandler{
		config: cfg,
	}

	sessionID := uuid.Must(uuid.NewV4()).String()

	packets := []struct {
		seq     uint64
		payload string
	}{
		{5, "five"},
		{2, "two"},
		{0, "zero"},
		{3, "three"},
		{1, "one"},
		{4, "four"},
	}

	for _, p := range packets {
		body := bytes.NewReader([]byte(p.payload))
		req := httptest.NewRequest("POST", "/xhttp/"+sessionID+"/"+string(rune('0'+p.seq)), body)
		w := httptest.NewRecorder()
		handler.handlePacketUpload(w, req, sessionID, p.seq)
	}

	session, _ := handler.getOrCreateSession(sessionID)
	time.Sleep(20 * time.Millisecond)

	expected := []string{"zero", "one", "two", "three", "four", "five"}
	buf := make([]byte, 100)

	for i, exp := range expected {
		n, err := session.uploadQueue.Read(buf)
		if err != nil {
			t.Fatalf("Read %d failed: %v", i, err)
		}
		if string(buf[:n]) != exp {
			t.Errorf("Read %d: got %s, want %s", i, string(buf[:n]), exp)
		}
	}

	session.uploadQueue.Close()
}

func TestBufferOverflow(t *testing.T) {
	cfg := &Config{
		ScMaxBufferedPosts: Range{From: 2, To: 2},
	}
	cfg.normalize()
	handler := &requestHandler{
		config: cfg,
	}

	sessionID := uuid.Must(uuid.NewV4()).String()
	session, _ := handler.getOrCreateSession(sessionID)

	for i := 0; i < 100; i++ {
		err := session.uploadQueue.Push(Packet{
			Payload: []byte("overflow"),
			Seq:     uint64(i),
		})
		if err == io.ErrShortBuffer {
			return
		}
	}
	t.Error("Expected ErrShortBuffer but uploads succeeded")
}

package route

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// Bound writes only after a Close frame, including a snapshot already in progress.
const connectionCloseGrace = 5 * time.Second

func connectionRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConnections)
	r.Delete("/", closeAllConnections)
	r.Delete("/{id}", closeConnection)
	return r
}

func getConnections(w http.ResponseWriter, r *http.Request) {
	if !(r.Header.Get("Upgrade") == "websocket") {
		snapshot := statistic.DefaultManager.Snapshot()
		render.JSON(w, r, snapshot)
		return
	}

	intervalStr := r.URL.Query().Get("interval")
	interval := int64(1000)
	if intervalStr != "" {
		t, err := strconv.ParseInt(intervalStr, 10, 64)
		if err != nil || t <= 0 || t > math.MaxInt64/int64(time.Millisecond) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		interval = t
	}
	conn, rw, err := wsUpgrade(r, w)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	stopCancel := contextutils.AfterFunc(r.Context(), func() { _ = conn.Close() })
	defer stopCancel()
	controls := make(chan wsutil.Message, 4)
	stopReading := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		readConnectionControls(conn, rw.Reader, controls, stopReading)
	}()
	defer func() {
		close(stopReading)
		_ = conn.Close()
		<-readerDone
	}()

	buf := &bytes.Buffer{}
	sendSnapshot := func() error {
		buf.Reset()
		snapshot := statistic.DefaultManager.Snapshot()
		if err := json.NewEncoder(buf).Encode(snapshot); err != nil {
			return err
		}

		return wsWriteServerText(conn, buf.Bytes())
	}

	if err := sendSnapshot(); err != nil {
		return
	}

	tick := time.NewTicker(time.Millisecond * time.Duration(interval))
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case message, ok := <-controls:
			if !ok || wsutil.HandleClientControlMessage(conn, message) != nil {
				return
			}
		case <-tick.C:
			if err := sendSnapshot(); err != nil {
				return
			}
		}
	}
}

// Only this handler writes frames. The reader closes the socket on EOF to
// interrupt a blocked snapshot write, and never queues unbounded client data.
func readConnectionControls(conn net.Conn, source io.Reader, controls chan<- wsutil.Message, stop <-chan struct{}) {
	defer close(controls)
	defer conn.Close()
	reader := wsutil.Reader{Source: source, State: ws.StateServerSide, CheckUTF8: true}
	handleControl := func(header ws.Header, source io.Reader) error {
		payload, err := io.ReadAll(source) // Validated control frames are at most 125 bytes.
		if err != nil {
			return err
		}
		isClose := header.OpCode == ws.OpClose
		if isClose {
			if err := conn.SetWriteDeadline(time.Now().Add(connectionCloseGrace)); err != nil {
				return err
			}
		}
		select {
		case controls <- wsutil.Message{OpCode: header.OpCode, Payload: payload}:
			if isClose {
				// Preserve the read half until the handler writes its Close reply.
				<-stop
				return io.EOF
			}
			return nil
		case <-stop:
			return io.EOF
		default:
			// A blocked writer must not also retain a blocked control reader.
			return io.ErrShortBuffer
		}
	}
	reader.OnIntermediate = handleControl
	for {
		header, err := reader.NextFrame()
		if err != nil {
			return
		}
		if header.OpCode.IsControl() {
			err = handleControl(header, &reader)
		} else {
			err = reader.Discard()
		}
		if err != nil {
			return
		}
	}
}

func closeConnection(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if c := statistic.DefaultManager.Get(id); c != nil {
		_ = c.Close()
	}
	render.NoContent(w, r)
}

func closeAllConnections(w http.ResponseWriter, r *http.Request) {
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		_ = c.Close()
		return true
	})
	render.NoContent(w, r)
}

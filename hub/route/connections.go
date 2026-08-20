package route

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

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
	interval := time.Second
	if intervalStr != "" {
		const maxIntervalMilliseconds = (1<<63 - 1) / int64(time.Millisecond)
		milliseconds, err := strconv.ParseInt(intervalStr, 10, 64)
		if err != nil || milliseconds <= 0 || milliseconds > maxIntervalMilliseconds {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		interval = time.Duration(milliseconds) * time.Millisecond
	}

	conn, _, err := wsUpgrade(r, w)
	if err != nil {
		return
	}
	defer conn.Close()
	snapshotStream := statistic.DefaultManager.NewSnapshotStream()
	defer snapshotStream.Close()

	buf := &bytes.Buffer{}
	sendSnapshot := func() error {
		buf.Reset()
		snapshot := snapshotStream.Snapshot()
		if err := json.NewEncoder(buf).Encode(snapshot); err != nil {
			return err
		}
		if err := conn.SetWriteDeadline(time.Now().Add(C.DefaultTCPTimeout)); err != nil {
			return err
		}

		return wsWriteServerText(conn, buf.Bytes())
	}

	if err := sendSnapshot(); err != nil {
		return
	}

	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
		case <-snapshotStream.Updates():
		}
		if err := sendSnapshot(); err != nil {
			break
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

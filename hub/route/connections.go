package route

import (
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

	sendSnapshot := func() error {
		snapshot := snapshotStream.Snapshot()
		data, err := json.Marshal(snapshot)
		if err != nil {
			return err
		}
		if err := conn.SetWriteDeadline(time.Now().Add(C.DefaultTCPTimeout)); err != nil {
			return err
		}

		return wsWriteServerText(conn, data)
	}

	if err := sendSnapshot(); err != nil {
		return
	}

	nextSnapshot := time.Now().Add(interval)
	timer := time.NewTimer(interval)
	defer timer.Stop()
	updates := snapshotStream.Updates()
	for {
		select {
		case <-timer.C:
		case <-updates:
			updates = nil
			if time.Until(nextSnapshot) > C.DefaultTCPTimeout {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(C.DefaultTCPTimeout)
				nextSnapshot = time.Now().Add(C.DefaultTCPTimeout)
			}
			continue
		}
		if err := sendSnapshot(); err != nil {
			break
		}
		timer.Reset(interval)
		nextSnapshot = time.Now().Add(interval)
		updates = snapshotStream.Updates()
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

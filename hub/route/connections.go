package route

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
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
		snapshots := statistic.Snapshots()
		render.JSON(w, r, snapshots)
		return
	}

	conn, _, _, err := ws.UpgradeHTTP(r, w)
	if err != nil {
		return
	}

	intervalStr := r.URL.Query().Get("interval")
	interval := 1000
	if intervalStr != "" {
		t, err := strconv.Atoi(intervalStr)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		interval = t
	}

	buf := &bytes.Buffer{}
	sendSnapshot := func() error {
		buf.Reset()
		snapshots := statistic.Snapshots()
		if err := json.NewEncoder(buf).Encode(snapshots); err != nil {
			return err
		}

		return wsutil.WriteMessage(conn, ws.StateServerSide, ws.OpText, buf.Bytes())
	}

	if err := sendSnapshot(); err != nil {
		return
	}

	tick := time.NewTicker(time.Millisecond * time.Duration(interval))
	defer tick.Stop()
	for range tick.C {
		if err := sendSnapshot(); err != nil {
			break
		}
	}
}

func closeConnection(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
here:
	for _, manager := range statistic.ChannelManager {
		if c := manager.Get(id); c != nil {
			_ = c.Close()
			break here
		}

	}
	render.NoContent(w, r)
}

func closeAllConnections(w http.ResponseWriter, r *http.Request) {
	for _, v := range statistic.ChannelManager {
		v.Range(func(c statistic.Tracker) bool {
			_ = c.Close()
			return true
		})
	}
	render.NoContent(w, r)
}

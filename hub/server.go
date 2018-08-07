package hub

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	T "github.com/Dreamacro/clash/tunnel"

	"github.com/go-chi/chi"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
	log "github.com/sirupsen/logrus"
)

type Traffic struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

func newHub(signal chan struct{}) {
	var addr string
	ch := config.Instance().Subscribe()
	signal <- struct{}{}
	for {
		elm := <-ch
		event := elm.(*config.Event)
		if event.Type == "external-controller" {
			addr = event.Payload.(string)
			break
		}
	}

	r := chi.NewRouter()

	cors := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type"},
		MaxAge:         300,
	})

	r.Use(cors.Handler)

	r.With(jsonContentType).Get("/traffic", traffic)
	r.With(jsonContentType).Get("/logs", getLogs)
	r.Mount("/configs", configRouter())
	r.Mount("/proxies", proxyRouter())
	r.Mount("/rules", ruleRouter())

	err := http.ListenAndServe(addr, r)
	if err != nil {
		log.Errorf("External controller error: %s", err.Error())
	}
}

func jsonContentType(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func traffic(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	tick := time.NewTicker(time.Second)
	t := tunnel.Traffic()
	for range tick.C {
		up, down := t.Now()
		if err := json.NewEncoder(w).Encode(Traffic{
			Up:   up,
			Down: down,
		}); err != nil {
			break
		}
		w.(http.Flusher).Flush()
	}
}

type GetLogs struct {
	Level string `json:"level"`
}

type Log struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

func getLogs(w http.ResponseWriter, r *http.Request) {
	req := &GetLogs{}
	render.DecodeJSON(r.Body, req)
	if req.Level == "" {
		req.Level = "info"
	}

	level, ok := C.LogLevelMapping[req.Level]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, Error{
			Error: "Level error",
		})
		return
	}

	src := tunnel.Log()
	sub, err := src.Subscribe()
	defer src.UnSubscribe(sub)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		render.JSON(w, r, Error{
			Error: err.Error(),
		})
		return
	}
	render.Status(r, http.StatusOK)
	for elm := range sub {
		log := elm.(T.Log)
		if log.LogLevel > level {
			continue
		}

		if err := json.NewEncoder(w).Encode(Log{
			Type:    log.Type(),
			Payload: log.Payload,
		}); err != nil {
			break
		}
		w.(http.Flusher).Flush()
	}
}

// Run initial hub
func Run() {
	signal := make(chan struct{})
	go newHub(signal)
	<-signal
}

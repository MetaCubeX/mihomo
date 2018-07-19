package hub

import (
	"encoding/json"
	"net/http"
	"time"

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

func NewHub(addr string) {
	r := chi.NewRouter()

	cors := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type"},
		MaxAge:         300,
	})

	r.Use(cors.Handler)

	r.Get("/traffic", traffic)
	r.Get("/logs", getLogs)
	r.Mount("/configs", configRouter())
	r.Mount("/proxies", proxyRouter())
	r.Mount("/rules", ruleRouter())

	err := http.ListenAndServe(addr, r)
	if err != nil {
		log.Fatalf("External controller error: %s", err.Error())
	}
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

	mapping := map[string]T.LogLevel{
		"info":    T.INFO,
		"debug":   T.DEBUG,
		"error":   T.ERROR,
		"warning": T.WARNING,
	}

	level, ok := mapping[req.Level]
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

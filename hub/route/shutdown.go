package route

import (
	"net/http"
	"os"

	"github.com/metacubex/mihomo/hub/executor"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func shutdownRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/", shutdown)
	return r
}

func shutdown(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"status": "ok"})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	go shutdownExecutable()
}

func shutdownExecutable() {
	executor.Shutdown()
	os.Exit(0)
}

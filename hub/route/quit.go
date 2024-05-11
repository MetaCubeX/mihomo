package route

import (
	"net/http"
	"runtime"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/metacubex/mihomo/hub/executor"
)

func quitRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", quitCore)
	return r
}

func quitCore(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"status": "ok"})
	executor.Shutdown()
	if runtime.GOOS == "windows" {
		os.Exit(0)
	}
}
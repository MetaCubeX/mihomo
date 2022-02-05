package route

import (
	"github.com/go-chi/chi/v5"
	"net/http"
)

func scriptRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getScript)
	return r
}

func getScript(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusMethodNotAllowed)
}

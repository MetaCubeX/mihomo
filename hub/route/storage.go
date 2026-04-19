package route

import (
	"encoding/json"
	"io"

	"github.com/metacubex/mihomo/component/profile/cachefile"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func storageRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/{key}", getStorage)
	r.Put("/{key}", setStorage)
	r.Delete("/{key}", deleteStorage)
	return r
}

func getStorage(w http.ResponseWriter, r *http.Request) {
	key := getEscapeParam(r, "key")
	data := cachefile.Cache().GetStorage(key)
	w.Header().Set("Content-Type", "application/json")
	if len(data) == 0 {
		w.Write([]byte("null"))
		return
	}
	w.Write(data)
}

func setStorage(w http.ResponseWriter, r *http.Request) {
	key := getEscapeParam(r, "key")
	data, err := io.ReadAll(r.Body)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	if !json.Valid(data) {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	if len(data) > 1024*1024 {
		render.Status(r, http.StatusRequestEntityTooLarge)
		render.JSON(w, r, newError("payload exceeds 1MB limit"))
		return
	}
	cachefile.Cache().SetStorage(key, data)
	render.NoContent(w, r)
}

func deleteStorage(w http.ResponseWriter, r *http.Request) {
	key := getEscapeParam(r, "key")
	cachefile.Cache().DeleteStorage(key)
	render.NoContent(w, r)
}

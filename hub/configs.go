package hub

import (
	"fmt"
	"net/http"

	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

func configRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConfigs)
	r.Put("/", updateConfigs)
	return r
}

type configSchema struct {
	Port      int    `json:"port"`
	SocksPort int    `json:"socket-port"`
	RedirPort int    `json:"redir-port"`
	AllowLan  bool   `json:"allow-lan"`
	Mode      string `json:"mode"`
	LogLevel  string `json:"log-level"`
}

func getConfigs(w http.ResponseWriter, r *http.Request) {
	general := cfg.General()
	render.JSON(w, r, configSchema{
		Port:      general.Port,
		SocksPort: general.SocksPort,
		RedirPort: general.RedirPort,
		AllowLan:  general.AllowLan,
		Mode:      general.Mode.String(),
		LogLevel:  general.LogLevel.String(),
	})
}

func updateConfigs(w http.ResponseWriter, r *http.Request) {
	general := &C.General{}
	err := render.DecodeJSON(r.Body, general)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, Error{
			Error: "Format error",
		})
		return
	}

	// update errors
	var modeErr, logLevelErr error

	// update mode
	if general.Mode != nil {
		mode, ok := config.ModeMapping[*general.Mode]
		if !ok {
			modeErr = fmt.Errorf("Mode error")
		} else {
			cfg.SetMode(mode)
		}
	}

	// update log-level
	if general.LogLevel != nil {
		level, ok := C.LogLevelMapping[*general.LogLevel]
		if !ok {
			logLevelErr = fmt.Errorf("Log Level error")
		} else {
			cfg.SetLogLevel(level)
		}
	}

	hasError, errors := formatErrors(map[string]error{
		"mode":      modeErr,
		"log-level": logLevelErr,
	})

	if hasError {
		w.WriteHeader(http.StatusBadRequest)
		render.JSON(w, r, errors)
		return
	}

	// update proxy
	cfg.UpdateProxy(config.ProxyConfig{
		AllowLan:  general.AllowLan,
		Port:      general.Port,
		SocksPort: general.SocksPort,
		RedirPort: general.RedirPort,
	})

	w.WriteHeader(http.StatusNoContent)
}

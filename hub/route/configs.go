package route

import (
	"github.com/Dreamacro/clash/component/dialer"
	"net/http"
	"path/filepath"
	"sync"

	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/config"
	"github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/hub/executor"
	P "github.com/Dreamacro/clash/listener"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

var (
	updateGeoMux sync.Mutex
	updatingGeo  = false
)

func configRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConfigs)
	r.Put("/", updateConfigs)
	r.Post("/geo", updateGeoDatabases)
	r.Patch("/", patchConfigs)
	return r
}

type configSchema struct {
	Port          *int               `json:"port"`
	SocksPort     *int               `json:"socks-port"`
	RedirPort     *int               `json:"redir-port"`
	TProxyPort    *int               `json:"tproxy-port"`
	MixedPort     *int               `json:"mixed-port"`
	Tun           *config.Tun        `json:"tun"`
	AllowLan      *bool              `json:"allow-lan"`
	BindAddress   *string            `json:"bind-address"`
	Mode          *tunnel.TunnelMode `json:"mode"`
	LogLevel      *log.LogLevel      `json:"log-level"`
	IPv6          *bool              `json:"ipv6"`
	Sniffing      *bool              `json:"sniffing"`
	TcpConcurrent *bool              `json:"tcp-concurrent"`
}

func getConfigs(w http.ResponseWriter, r *http.Request) {
	general := executor.GetGeneral()
	render.JSON(w, r, general)
}

func pointerOrDefault(p *int, def int) int {
	if p != nil {
		return *p
	}

	return def
}

func patchConfigs(w http.ResponseWriter, r *http.Request) {
	general := &configSchema{}
	if err := render.DecodeJSON(r.Body, general); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	if general.AllowLan != nil {
		P.SetAllowLan(*general.AllowLan)
	}

	if general.BindAddress != nil {
		P.SetBindAddress(*general.BindAddress)
	}

	if general.Sniffing != nil {
		tunnel.SetSniffing(*general.Sniffing)
	}

	if general.TcpConcurrent != nil {
		dialer.SetDial(*general.TcpConcurrent)
	}

	ports := P.GetPorts()

	tcpIn := tunnel.TCPIn()
	udpIn := tunnel.UDPIn()

	P.ReCreateHTTP(pointerOrDefault(general.Port, ports.Port), tcpIn)
	P.ReCreateSocks(pointerOrDefault(general.SocksPort, ports.SocksPort), tcpIn, udpIn)
	P.ReCreateRedir(pointerOrDefault(general.RedirPort, ports.RedirPort), tcpIn, udpIn)
	P.ReCreateTProxy(pointerOrDefault(general.TProxyPort, ports.TProxyPort), tcpIn, udpIn)
	P.ReCreateMixed(pointerOrDefault(general.MixedPort, ports.MixedPort), tcpIn, udpIn)

	if general.Mode != nil {
		tunnel.SetMode(*general.Mode)
	}

	if general.LogLevel != nil {
		log.SetLevel(*general.LogLevel)
	}

	if general.IPv6 != nil {
		resolver.DisableIPv6 = !*general.IPv6
	}

	render.NoContent(w, r)
}

type updateConfigRequest struct {
	Path    string `json:"path"`
	Payload string `json:"payload"`
}

func updateConfigs(w http.ResponseWriter, r *http.Request) {
	req := updateConfigRequest{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	force := r.URL.Query().Get("force") == "true"
	var cfg *config.Config
	var err error

	if req.Payload != "" {
		cfg, err = executor.ParseWithBytes([]byte(req.Payload))
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	} else {
		if req.Path == "" {
			req.Path = constant.Path.Config()
		}
		if !filepath.IsAbs(req.Path) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("path is not a absolute path"))
			return
		}

		cfg, err = executor.ParseWithPath(req.Path)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	}

	executor.ApplyConfig(cfg, force)
	render.NoContent(w, r)
}

func updateGeoDatabases(w http.ResponseWriter, r *http.Request) {
	updateGeoMux.Lock()

	if updatingGeo {
		updateGeoMux.Unlock()
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("updating..."))
		return
	}

	updatingGeo = true
	updateGeoMux.Unlock()

	go func() {
		defer func() {
			updatingGeo = false
		}()

		log.Warnln("[REST-API] updating GEO databases...")

		if err := config.UpdateGeoDatabases(); err != nil {
			log.Errorln("[REST-API] update GEO databases failed: %v", err)
			return
		}

		cfg, err := executor.ParseWithPath(constant.Path.Config())
		if err != nil {
			log.Errorln("[REST-API] update GEO databases failed: %v", err)
			return
		}

		log.Warnln("[REST-API] update GEO databases successful, apply config...")

		executor.ApplyConfig(cfg, false)
	}()

	render.NoContent(w, r)
}

package hub

import (
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/log"
)

type Option func(*config.Config)

func WithExternalUI(externalUI string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalUI = externalUI
	}
}

func WithExternalController(externalController string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalController = externalController
	}
}

func WithExternalControllerUnix(externalControllerUnix string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalControllerUnix = externalControllerUnix
	}
}

func WithExternalControllerPipe(externalControllerPipe string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalControllerPipe = externalControllerPipe
	}
}

func WithSecret(secret string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.Secret = secret
	}
}

// ApplyConfig dispatch configure to all parts include ExternalController
func ApplyConfig(cfg *config.Config) {
	applyRoute(cfg)
	executor.ApplyConfig(cfg, true)
}

func applyRoute(cfg *config.Config) {
	if cfg.Controller.ExternalUI != "" {
		route.SetUIPath(cfg.Controller.ExternalUI)
	}
	route.ReCreateServer(&route.Config{
		Addr:        cfg.Controller.ExternalController,
		TLSAddr:     cfg.Controller.ExternalControllerTLS,
		UnixAddr:    cfg.Controller.ExternalControllerUnix,
		PipeAddr:    cfg.Controller.ExternalControllerPipe,
		Secret:      cfg.Controller.Secret,
		Certificate: cfg.TLS.Certificate,
		PrivateKey:  cfg.TLS.PrivateKey,
		DohServer:   cfg.Controller.ExternalDohServer,
		IsDebug:     cfg.General.LogLevel == log.DEBUG,
	})
}

// Parse call at the beginning of mihomo
func Parse(configBytes []byte, options ...Option) error {
	var cfg *config.Config
	var err error

	if len(configBytes) != 0 {
		cfg, err = executor.ParseWithBytes(configBytes)
	} else {
		cfg, err = executor.Parse()
	}

	if err != nil {
		return err
	}

	for _, option := range options {
		option(cfg)
	}

	ApplyConfig(cfg)
	return nil
}

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

func WithSecret(secret string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.Secret = secret
	}
}

// Parse call at the beginning of mihomo
func Parse(options ...Option) error {
	cfg, err := executor.Parse()
	if err != nil {
		return err
	}

	for _, option := range options {
		option(cfg)
	}

	if cfg.Controller.ExternalUI != "" {
		route.SetUIPath(cfg.Controller.ExternalUI)
	}

	if cfg.Controller.ExternalController != "" {
		go route.Start(cfg.Controller.ExternalController, cfg.Controller.ExternalControllerTLS,
			cfg.Controller.Secret, cfg.TLS.Certificate, cfg.TLS.PrivateKey, cfg.Controller.ExternalDohServer,
			cfg.General.LogLevel == log.DEBUG)
	}

	if cfg.Controller.ExternalControllerUnix != "" {
		go route.StartUnix(cfg.Controller.ExternalControllerUnix, cfg.Controller.ExternalDohServer, cfg.General.LogLevel == log.DEBUG)
	}

	executor.ApplyConfig(cfg, true)
	return nil
}

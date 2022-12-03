package hub

import (
	"errors"

	"github.com/Dreamacro/clash/config"
	"github.com/Dreamacro/clash/hub/executor"
	"github.com/Dreamacro/clash/hub/route"
)

type Option func(*config.Config)

func WithExternalUI(externalUI string) Option {
	return func(cfg *config.Config) {
		cfg.General.ExternalUI = externalUI
	}
}

func WithExternalController(externalController string) Option {
	return func(cfg *config.Config) {
		cfg.General.ExternalController = externalController
	}
}

func WithSecret(secret string) Option {
	return func(cfg *config.Config) {
		cfg.General.Secret = secret
	}
}

// Parse call at the beginning of clash
func Parse(options ...Option) error {
	cfg, err := executor.Parse()
	if err != nil {
		return err
	}

	for _, option := range options {
		option(cfg)
	}

	if cfg.General.ExternalUI != "" {
		route.SetUIPath(cfg.General.ExternalUI)
	}

	if cfg.General.ExternalController != "" {
		if cfg.General.TLSPort != 0 && (len(cfg.General.PrivateKey) == 0 || len(cfg.General.Cert) == 0) {
			return errors.New("Must be provided certificates and keys, for tls controller")
		}

		go route.Start(cfg.General.ExternalController, cfg.General.Secret, cfg.General.TLSPort,
			cfg.General.Cert, cfg.General.PrivateKey)
	}

	executor.ApplyConfig(cfg, true)
	return nil
}

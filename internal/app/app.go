// Package app loads the configuration and wires the services, modules and
// middleware into a gas application.
package app

import (
	"fmt"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/httpx"
	"tule.dev/secret-store/internal/modules/health"
	"tule.dev/secret-store/internal/modules/secret"
	"tule.dev/secret-store/internal/services/secrets/dirimpl"
	"tule.dev/secret-store/internal/sigv4"
)

// New builds the application from cfg. extra options are applied after the
// app's own.
func New(cfg *Config, extra ...gas.Option) (*gas.App, error) {
	logger, lErr := newLogger(cfg.Env)
	if lErr != nil {
		return nil, lErr
	}

	// Every request is a POST authenticated by its signature, not by a
	// cookie, so the cross-origin protection meant for browser sessions would
	// reject every call an SDK makes.
	opts := append([]gas.Option{gas.WithCSRFInsecureBypassPattern("/")}, extra...)
	app := gas.NewApp(opts...)

	registerInfraServices(app, cfg, logger)
	registerAppServices(app, cfg)
	registerAppModules(app)
	installMiddleware(app.Router(), cfg)
	app.ReadyFunc(seedSecrets(cfg.Store.Seed))

	return app, nil
}

func registerInfraServices(app *gas.App, cfg *Config, logger gas.Logger) {
	app.RegisterServiceInstance[gas.ConfigProvider](cfg.store)
	app.RegisterServiceInstance[gas.Logger](logger)
	app.RegisterScopedService[httpx.RequestLogger](resolveRequestLogger)
}

func registerAppServices(app *gas.App, cfg *Config) {
	app.RegisterSingletonService[contracts.SecretsProvider](dirimpl.NewService(cfg.Store))
}

func registerAppModules(app *gas.App) {
	app.RegisterSingletonService[*secret.Module](secret.NewModule)
	app.RegisterSingletonService[*health.Module](health.NewModule)
}

func installMiddleware(r *gas.Router, cfg *Config) {
	r.UseMiddlewareFunc(httpx.RequestID(cfg.Env))

	// No X-Forwarded-For handling: nothing is expected in front of this
	// service, and the header is unsigned, so trusting a hop would only let a
	// caller choose the client IP that ends up in the logs.

	r.UseMiddlewareFunc(withRequestLogger)

	r.UseMiddlewareFunc(gas.RequestLogger[httpx.RequestLogger]())

	r.UseMiddlewareFunc(verifySignature(sigv4.NewVerifier(sigv4.Credentials{
		AccessKeyID:     cfg.Auth.AccessKeyID,
		SecretAccessKey: cfg.Auth.SecretAccessKey,
	})))

	var hsts string
	if cfg.HSTS != nil && cfg.HSTS.MaxAge > 0 {
		hsts = fmt.Sprintf("max-age=%0.f", cfg.HSTS.MaxAge.Seconds())
	}
	r.UseMiddlewareFunc(gas.SecurityHeaders(
		gas.WithSecurityHeadersStrictTransportSecurity(hsts),
	))
}

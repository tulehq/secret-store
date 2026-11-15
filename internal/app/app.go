// Package app loads the configuration and wires the services, modules and
// middleware into a gas application.
package app

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gasmod/gas"
	"tule.dev/functions/serviceinvoke"
	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/authz"
	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/httpx"
	"tule.dev/secret-store/internal/modules/health"
	"tule.dev/secret-store/internal/modules/secret"
	"tule.dev/secret-store/internal/services/rotation"
	"tule.dev/secret-store/internal/services/secrets/dirimpl"
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

	verifier, vErr := newVerifier(cfg.Auth, cfg.Store.AccountID)
	if vErr != nil {
		return nil, vErr
	}

	az := authz.New(cfg.Store.Region, cfg.Store.AccountID)

	pp, pErr := newPolicyPrincipals(cfg.Auth)
	if pErr != nil {
		return nil, pErr
	}

	rs, rErr := newRotationSettings(app, cfg, logger)
	if rErr != nil {
		return nil, rErr
	}

	registerInfraServices(app, cfg, logger)
	registerAppServices(app, cfg, az, pp, rs)
	registerAppModules(app)
	installMiddleware(app.Router(), cfg, logger, verifier, az)
	app.ReadyFunc(seedSecrets(cfg.Store.Seed))

	return app, nil
}

func registerInfraServices(app *gas.App, cfg *Config, logger gas.Logger) {
	app.RegisterServiceInstance[gas.ConfigProvider](cfg.store)
	app.RegisterServiceInstance[gas.Logger](logger)
	app.RegisterScopedService[httpx.RequestLogger](resolveRequestLogger)
}

func registerAppServices(
	app *gas.App,
	cfg *Config,
	az *authz.Authorizer,
	pp contracts.PolicyPrincipals,
	rs rotation.Settings,
) {
	app.RegisterSingletonService[contracts.SecretsProvider](dirimpl.NewService(cfg.Store))
	app.RegisterServiceInstance[*authz.Authorizer](az)
	app.RegisterServiceInstance[contracts.PolicyPrincipals](pp)
	// The rotation service depends on the store, so gas closes it, and
	// stops its runs, before the store.
	app.RegisterSingletonService[contracts.Rotations](rotation.NewService(rs))
}

// functionsTimeout bounds one call to the functions service's
// service-invoke endpoint: a synchronous invocation runs as long as the
// function, whose timeout is at most 900 seconds, and the minute beyond it
// leaves the endpoint time to answer.
const functionsTimeout = 16 * time.Minute

// newRotationSettings returns the rotation service's settings: an invoker
// for the functions endpoint, or none, when it is not set, to leave
// rotation unserved, and the wait for app's server to listen.
func newRotationSettings(app *gas.App, cfg *Config, logger gas.Logger) (rotation.Settings, error) {
	rs := rotation.Settings{Clock: cfg.rotationClock}
	if cfg.Store.FunctionsEndpoint == "" {
		return rs, nil
	}
	listening := subscribeListening(app)
	rs.WaitServing = func(ctx context.Context) error {
		return waitListening(ctx, listening, logger, listenWarnAfter, listenWarnEvery)
	}
	c, err := serviceinvoke.New(serviceinvoke.Config{
		HTTPClient:      &http.Client{Timeout: functionsTimeout},
		Endpoint:        cfg.Store.FunctionsEndpoint,
		Region:          cfg.Store.Region,
		AccessKeyID:     cfg.Auth.AccessKeyID,
		SecretAccessKey: cfg.Auth.SecretAccessKey,
	})
	if err != nil {
		return rs, fmt.Errorf("functions service-invoke client: %w", err)
	}
	rs.Invoker = rotation.NewFunctionsInvoker(c, cfg.Store.AccountID)
	return rs, nil
}

func registerAppModules(app *gas.App) {
	app.RegisterSingletonService[*secret.Module](secret.NewModule)
	app.RegisterSingletonService[*health.Module](health.NewModule)
}

func installMiddleware(
	r *gas.Router,
	cfg *Config,
	logger gas.Logger,
	v *sigv4.Verifier,
	az *authz.Authorizer,
) {
	r.UseMiddlewareFunc(nil, httpx.RequestID(cfg.Env))

	// No X-Forwarded-For handling: nothing is expected in front of this
	// service, and the header is unsigned, so trusting a hop would only let a
	// caller choose the client IP that ends up in the logs.

	r.UseMiddlewareFunc(nil, withRequestLogger(logger))

	r.UseMiddlewareFunc(nil, gas.RequestLogger[httpx.RequestLogger]())

	r.UseMiddlewareFunc(nil, verifySignature(v, az))

	var hsts string
	if cfg.HSTS != nil && cfg.HSTS.MaxAge > 0 {
		hsts = fmt.Sprintf("max-age=%0.f", cfg.HSTS.MaxAge.Seconds())
	}
	r.UseMiddlewareFunc(nil, gas.SecurityHeaders(
		gas.WithSecurityHeadersStrictTransportSecurity(hsts),
	))

	installUnrouted(r)
}

// listenWarnAfter is how long waitListening waits before it says so in the
// log, and listenWarnEvery how often it says so again.
const (
	listenWarnAfter = 5 * time.Second
	listenWarnEvery = 30 * time.Second
)

// subscribeListening returns a channel closed once the app's server
// listens: gas emits SystemServerListening once Serve or ServeListener has
// bound the listener, which is after Start, where the services, and so the
// rotations resumed at Init, start. The subscription is the app's, not the
// rotation service's, so it outlives a RestartService of that service,
// which would otherwise subscribe again after the one-shot event.
func subscribeListening(app *gas.App) <-chan struct{} {
	listening := make(chan struct{})
	var once sync.Once
	app.EventBus().Subscribe[gas.SystemServerListening](func(gas.SystemServerListeningPayload) {
		once.Do(func() { close(listening) })
	})
	return listening
}

// waitListening returns once listening is closed, or with ctx's error. The
// rotation service waits here before invoking any function, whose calls
// back would otherwise be refused. Once it has waited warnAfter, it logs a
// warning, and again every warnEvery, so a server that never listens is
// not a silent stall.
func waitListening(
	ctx context.Context,
	listening <-chan struct{},
	logger gas.Logger,
	warnAfter, warnEvery time.Duration,
) error {
	started := time.Now()
	warn := time.NewTimer(warnAfter)
	defer warn.Stop()
	for {
		select {
		case <-listening:
			return nil
		case <-ctx.Done():
			return fmt.Errorf("waiting for the server to listen: %w", ctx.Err())
		case <-warn.C:
			logger.Warn("rotations are waiting for the server to listen; none runs until it does").
				Duration("waited", time.Since(started)).Send()
			warn.Reset(warnEvery)
		}
	}
}

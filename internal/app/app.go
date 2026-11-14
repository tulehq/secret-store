// Package app loads the configuration and wires the services, modules and
// middleware into a gas application.
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
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

	rs, rErr := newRotationSettings(cfg, logger)
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
// rotation unserved, and the wait for the server to listen.
func newRotationSettings(cfg *Config, logger gas.Logger) (rotation.Settings, error) {
	rs := rotation.Settings{Clock: cfg.rotationClock}
	if cfg.Store.FunctionsEndpoint == "" {
		return rs, nil
	}
	addr, err := serverAddr(cfg)
	if err != nil {
		return rs, err
	}
	rs.WaitServing = func(ctx context.Context) error {
		return waitListening(ctx, addr, logger, listenWarnAfter, listenWarnEvery)
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

// serverAddr is the address the server is to listen on, from the Server
// settings gas serves with, as an address to dial (see dialAddr).
func serverAddr(cfg *Config) (string, error) {
	var bound struct {
		Server struct {
			Host string
			Port int
		}
	}
	if err := cfg.store.Bind(&bound); err != nil {
		return "", fmt.Errorf("config: the server address: %w", err)
	}
	return dialAddr(bound.Server.Host, bound.Server.Port)
}

// errPortZero refuses a server port of 0 with a functions endpoint. gas
// lets port 0 pick a free port, but exposes neither the listener nor the
// port it ends up on, so the rotation service could never find the server
// to wait for, and no rotation would ever run.
var errPortZero = errors.New("config: TULE_Server_Port 0 picks a free port, which the " +
	"rotation service cannot find to wait for before it invokes a rotation function; " +
	"set a fixed TULE_Server_Port when TULE_Store_FunctionsEndpoint is set")

// dialAddr is the address to dial to reach a server listening on host and
// port: every interface, gas's default, is dialed on loopback, as is an
// empty host; a named host or an address is dialed as it is. Port 0 is
// refused (errPortZero).
func dialAddr(host string, port int) (string, error) {
	if port == 0 {
		return "", errPortZero
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// listenPoll is how often waitListening dials the server. listenWarnAfter
// is how long it waits before it says so in the log, and listenWarnEvery
// how often it says so again.
const (
	listenPoll      = 100 * time.Millisecond
	listenWarnAfter = 5 * time.Second
	listenWarnEvery = 30 * time.Second
)

// waitListening returns once addr accepts a connection, or with ctx's
// error. gas has no event for the server starting to serve: Start, which
// initializes the services, returns before the server listens, so the
// rotation service, which may resume rotations at Init, waits here before
// invoking any function, whose calls back would otherwise be refused.
// Once it has waited warnAfter, it logs a warning naming addr, and again
// every warnEvery, so a server that never listens there is not a silent
// stall.
func waitListening(
	ctx context.Context,
	addr string,
	logger gas.Logger,
	warnAfter, warnEvery time.Duration,
) error {
	var d net.Dialer
	started := time.Now()
	nextWarn := started.Add(warnAfter)
	for {
		if now := time.Now(); !now.Before(nextWarn) {
			logger.Warn("rotations are waiting for the server to listen; none runs until it does").
				Str("address", addr).Duration("waited", now.Sub(started)).Send()
			nextWarn = now.Add(warnEvery)
		}
		dialCtx, cancel := context.WithTimeout(ctx, time.Second)
		conn, err := d.DialContext(dialCtx, "tcp", addr)
		cancel()
		if err == nil {
			// The probe was accepted, which is all it asks; a failure to
			// close it says nothing of the server.
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for %s to listen: %w", addr, ctx.Err())
		case <-time.After(listenPoll):
		}
	}
}

package app

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"

	"tule.dev/secret-store/internal/services/secrets/dirimpl"
)

// hstsSettings configures the Strict-Transport-Security header. It is only
// sent when MaxAge is set, so plain-HTTP deployments can leave it out.
type hstsSettings struct {
	MaxAge time.Duration
}

// authSettings holds the access key the server accepts. Every request must
// be SigV4-signed with it, or with a key the identity service issued, so both
// key fields are required.
//
// IdentityEndpoint is the identity service's base URL, or empty to accept the
// configured key alone. When it is set, the configured key must be identity's
// root key: it is what the calls to identity's signing-key endpoint are
// signed with.
type authSettings struct {
	AccessKeyID      string
	SecretAccessKey  string
	IdentityEndpoint string
}

// errNoCredentials is returned when the access key is not configured.
var errNoCredentials = errors.New("config: TULE_Auth_AccessKeyID and " +
	"TULE_Auth_SecretAccessKey must be set; every request is verified against them")

// Config is the bound application configuration. It keeps the store it was
// bound from, which the app registers as the gas.ConfigProvider so services
// can read settings Config itself does not model.
type Config struct {
	HSTS  *hstsSettings
	Auth  *authSettings
	Store *dirimpl.Settings `validate:"required"`

	store gas.ConfigProvider
	Env   config.Environment
}

const (
	envVarSeparator = "_"
	envVarPrefix    = "TULE_"
)

// LoadConfig loads configuration from a .env file and then the process
// environment, the later source winning. There is no Secrets Manager layer:
// this service is the one standing in for it.
func LoadConfig() (*Config, error) {
	return LoadConfigFrom(
		config.NewDotEnvProvider(
			config.WithDotEnvSeparator(envVarSeparator),
			config.WithDotEnvFileNotFoundPanic(false),
		),
		config.NewEnvProvider(
			config.WithEnvSeparator(envVarSeparator),
			config.WithEnvPrefix(envVarPrefix),
		),
	)
}

// LoadConfigFrom loads configuration from the given providers in order, then
// applies the same defaults and binding as LoadConfig. Tests use it to inject
// a provider of their own.
func LoadConfigFrom(provs ...config.Provider) (*Config, error) {
	env := config.NewEnvExtension()

	opts := make([]config.Option, 0, len(provs)+1)
	opts = append(opts, config.WithExtension(env))

	for _, p := range provs {
		opts = append(opts, config.WithProvider(p))
	}

	store := config.New(opts...)

	if err := store.Load(); err != nil {
		return nil, fmt.Errorf("config: load: %w", err)
	}

	return bindConfig(store, env.Current())
}

func bindConfig(store gas.ConfigProvider, env config.Environment) (*Config, error) {
	if err := applyDefaults(store); err != nil {
		return nil, err
	}

	cfg := Config{Env: env, store: store}
	if err := store.Bind(&cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if cfg.Auth == nil || cfg.Auth.AccessKeyID == "" || cfg.Auth.SecretAccessKey == "" {
		return nil, errNoCredentials
	}
	if err := checkIdentityEndpoint(cfg.Auth.IdentityEndpoint); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// checkIdentityEndpoint holds the identity endpoint, when set, to an
// absolute http or https URL.
func checkIdentityEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("config: Auth.IdentityEndpoint %q is not an http or https URL",
			endpoint)
	}
	return nil
}

func applyDefaults(store gas.ConfigProvider) error {
	var errs []error
	setDefault := func(key string, value any) {
		if err := store.SetDefault(key, value); err != nil {
			errs = append(errs, fmt.Errorf("config: default %s: %w", key, err))
		}
	}

	// 9010 rather than the 9000 object-store uses, so both can run at once.
	setDefault("Server.Port", 9010)

	// The server timeouts are set here rather than left to the gas defaults
	// (5s read, 10s write), which are too short for this service's requests.
	// A signed request body may be up to maxRequestBody, 1 MiB, and the
	// signature covers the whole body: a read cut short mid-body surfaces to
	// the client as a signature failure or a broken connection rather than as
	// a timeout, which is a confusing way to lose a 64 KiB secret over a slow
	// link. 30s covers 1 MiB at well under dial-up speed. Responses are
	// bounded by the same order of magnitude, a ListSecrets page or a
	// BatchGetSecretValue of several secrets, so writes get the same budget.
	// IdleTimeout keeps the SDKs' connection reuse working between calls, and
	// matches the gas default; it is set explicitly so it is visible here
	// rather than inherited.
	setDefault("Server.ReadTimeout", "30s")
	setDefault("Server.WriteTimeout", "30s")
	setDefault("Server.IdleTimeout", "120s")

	// The headers get the same 30s as the whole request. Before gas v0.6.0 they
	// were bounded by ReadTimeout, as net/http does when ReadHeaderTimeout
	// is unset, but gas requires ReadHeaderTimeout to be positive, so it
	// cannot be unlimited even when ReadTimeout is 0. Its gas default of 5s
	// would cut a slow client's headers short of the budget above.
	setDefault("Server.ReadHeaderTimeout", "30s")

	// ShutdownTimeout is shorter than the gas default of 30s, which is a
	// promise a container runtime does not keep: `docker stop` sends SIGTERM
	// and kills the process 10s later. Every request here is a small file
	// read or a single file rewrite, so in-flight work needs far less.
	//
	// It is not shorter than 7s because of a connection that was opened but
	// never sent a request, as an SDK client's spare one is. net/http closes
	// such a connection only once its whole-second timestamp is 6 seconds
	// old, 5s to 6s after it opened, and checks at most every 500ms, so the
	// shutdown can wait up to about 6.5s for it. With a shorter timeout gas
	// reports the deadline as an error and the process exits 1. Gas's
	// App.Stop returns within the timeout plus up to three 1s grace periods,
	// which only run while requests are still in flight: 10s at the very
	// worst, the edge of what docker gives.
	setDefault("Server.ShutdownTimeout", "7s")

	setDefault("Store.RootDir", "./data")
	// The region and account only appear in the ARNs the store mints; the
	// defaults match what the AWS SDKs use against a local endpoint.
	setDefault("Store.Region", "us-east-1")
	setDefault("Store.AccountID", "000000000000")

	return errors.Join(errs...)
}

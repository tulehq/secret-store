package app

import (
	"errors"
	"fmt"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"
	"github.com/gasmod/gas/config/extensions/gasenv"
	"github.com/gasmod/gas/config/providers"

	"tule.dev/secret-store/internal/services/secrets/dirimpl"
)

// hstsSettings configures the Strict-Transport-Security header. It is only
// sent when MaxAge is set, so plain-HTTP deployments can leave it out.
type hstsSettings struct {
	MaxAge time.Duration
}

// authSettings holds the one access key the server accepts. Every request
// must be SigV4-signed with it, so both fields are required.
type authSettings struct {
	AccessKeyID     string
	SecretAccessKey string
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
	Env   gasenv.Environment
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
		providers.NewDotEnvProvider(
			providers.WithDotEnvSeparator(envVarSeparator),
			providers.WithDotEnvFileNotFoundPanic(false),
		),
		providers.NewEnvProvider(
			providers.WithEnvSeparator(envVarSeparator),
			providers.WithEnvPrefix(envVarPrefix),
		),
	)
}

// LoadConfigFrom loads configuration from the given providers in order, then
// applies the same defaults and binding as LoadConfig. Tests use it to inject
// a provider of their own.
func LoadConfigFrom(provs ...providers.Provider) (*Config, error) {
	env := gasenv.NewExtension()

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

func bindConfig(store gas.ConfigProvider, env gasenv.Environment) (*Config, error) {
	applyDefaults(store)

	cfg := Config{Env: env, store: store}
	if err := store.Bind(&cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if cfg.Auth == nil || cfg.Auth.AccessKeyID == "" || cfg.Auth.SecretAccessKey == "" {
		return nil, errNoCredentials
	}

	return &cfg, nil
}

func applyDefaults(store gas.ConfigProvider) {
	// 9010 rather than the 9000 object-store uses, so both can run at once.
	store.SetDefault("Server.Port", 9010)

	// The server timeouts are set here rather than left to the gas defaults
	// (5s read, 10s write), which are too short for this service's requests.
	// A signed request body may be up to sigv4.MaxBodySize, 1 MiB, and the
	// signature covers the whole body: a read cut short mid-body surfaces to
	// the client as a signature failure or a broken connection rather than as
	// a timeout, which is a confusing way to lose a 64 KiB secret over a slow
	// link. 30s covers 1 MiB at well under dial-up speed. Responses are
	// bounded by the same order of magnitude, a ListSecrets page or a
	// BatchGetSecretValue of several secrets, so writes get the same budget.
	// IdleTimeout keeps the SDKs' connection reuse working between calls, and
	// matches the gas default; it is set explicitly so it is visible here
	// rather than inherited.
	store.SetDefault("Server.ReadTimeout", "30s")
	store.SetDefault("Server.WriteTimeout", "30s")
	store.SetDefault("Server.IdleTimeout", "120s")

	// ShutdownTimeout is shorter than the gas default of 30s, which is a
	// promise a container runtime does not keep: `docker stop` sends SIGTERM
	// and kills the process 10s later. Every request here is a small file
	// read or a single file rewrite, so 5s is far more than in-flight work
	// needs, and it leaves the rest of that window for the services to close
	// the storage root before the kill arrives.
	store.SetDefault("Server.ShutdownTimeout", "5s")

	store.SetDefault("Store.RootDir", "./data")
	// The region and account only appear in the ARNs the store mints; the
	// defaults match what the AWS SDKs use against a local endpoint.
	store.SetDefault("Store.Region", "us-east-1")
	store.SetDefault("Store.AccountID", "000000000000")
}

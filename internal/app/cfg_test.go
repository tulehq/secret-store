package app

import (
	"errors"
	"testing"
	"time"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config/providers"
)

func loadEnvConfig(t *testing.T, id, secret string) (*Config, error) {
	t.Helper()
	t.Setenv("TULE_GasEnv", "testing")
	t.Setenv("TULE_Auth_AccessKeyID", id)
	t.Setenv("TULE_Auth_SecretAccessKey", secret)

	return LoadConfigFrom(providers.NewEnvProvider(
		providers.WithEnvSeparator(envVarSeparator),
		providers.WithEnvPrefix(envVarPrefix),
	))
}

func TestLoadConfigRequiresCredentials(t *testing.T) {
	tests := []struct {
		name, id, secret string
		wantErr          bool
	}{
		{name: "both set", id: "AKID", secret: "secret"},
		{name: "neither set", wantErr: true},
		{name: "no secret", id: "AKID", wantErr: true},
		{name: "no access key", secret: "secret", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadEnvConfig(t, tt.id, tt.secret)
			if tt.wantErr != errors.Is(err, errNoCredentials) {
				t.Fatalf("got %v, want errNoCredentials: %v", err, tt.wantErr)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := loadEnvConfig(t, "AKID", "secret")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	// The ARNs the store mints depend on these, so a default that drifts
	// silently would change what clients see.
	if got := cfg.Store.Region; got != "us-east-1" {
		t.Fatalf("default region = %q, want us-east-1", got)
	}
	if got := cfg.Store.AccountID; got != "000000000000" {
		t.Fatalf("default account = %q, want 000000000000", got)
	}
	if got := cfg.Store.RootDir; got != "./data" {
		t.Fatalf("default root dir = %q, want ./data", got)
	}
	if got := cfg.store.Get("Server.Port"); got != 9010 {
		t.Fatalf("default port = %v, want 9010", got)
	}
}

func TestLoadConfigSetsServerTimeouts(t *testing.T) {
	cfg, err := loadEnvConfig(t, "AKID", "secret")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	// Bound through gas's own Config, so a key this service spells wrong
	// fails here rather than silently leaving the gas default in place.
	gasCfg := gas.DefaultConfig()
	if bErr := cfg.store.Bind(gasCfg); bErr != nil {
		t.Fatalf("bind gas config: %v", bErr)
	}

	tests := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{name: "read", got: gasCfg.Server.ReadTimeout, want: 30 * time.Second},
		{name: "write", got: gasCfg.Server.WriteTimeout, want: 30 * time.Second},
		{name: "idle", got: gasCfg.Server.IdleTimeout, want: 2 * time.Minute},
		{name: "shutdown", got: gasCfg.Server.ShutdownTimeout, want: 5 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s timeout = %s, want %s", tt.name, tt.got, tt.want)
			}
		})
	}
}

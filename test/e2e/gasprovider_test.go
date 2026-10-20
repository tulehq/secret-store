//go:build e2e

package e2e

import (
	"testing"

	"github.com/gasmod/gas/config"
	"github.com/gasmod/gas/config/providers/secretsmanager"
)

// TestGasConfigProvider is the compatibility target the service exists for:
// gas/config's Secrets Manager provider, pointed at this service with
// WithEndpoint, must resolve an app's config secrets.
func TestGasConfigProvider(t *testing.T) {
	srv := startServer(t, nil)
	c := clientFor(srv)

	// A root-merged secret holds a JSON object; a keyed secret holds a scalar
	// the provider nests at the key it was registered with.
	createSecret(t, c, "example/app", `{"Database":{"Host":"db.internal","Port":5432}}`)
	createSecret(t, c, "example/app/token", "s3cr3t-placeholder")

	store := config.New(
		config.WithProvider(secretsmanager.NewProvider(
			secretsmanager.WithEndpoint(srv.URL),
			secretsmanager.WithRegion("us-east-1"),
			secretsmanager.WithStaticCredentials("test", "test"),
			secretsmanager.WithSecret("example/app"),
			secretsmanager.WithSecretAtKey("example/app/token", "Database.Token"),
		)),
	)
	requireNoErr(t, store.Load(), "load config from the service")

	var cfg struct {
		Database struct {
			Host  string
			Token string
			Port  int
		}
	}
	requireNoErr(t, store.Bind(&cfg), "bind config")

	requireEqual(t, cfg.Database.Host, "db.internal", "root-merged secret")
	requireEqual(t, cfg.Database.Port, 5432, "root-merged secret")
	requireEqual(t, cfg.Database.Token, "s3cr3t-placeholder", "keyed secret")
}

// TestGasConfigProviderByARN resolves a secret the provider registered by its
// full ARN rather than its name.
func TestGasConfigProviderByARN(t *testing.T) {
	srv := startServer(t, nil)
	arn := createSecret(t, clientFor(srv), "example/arn", `{"Feature":{"Enabled":true}}`)

	store := config.New(
		config.WithProvider(secretsmanager.NewProvider(
			secretsmanager.WithEndpoint(srv.URL),
			secretsmanager.WithRegion("us-east-1"),
			secretsmanager.WithStaticCredentials("test", "test"),
			secretsmanager.WithSecret(arn),
		)),
	)
	requireNoErr(t, store.Load(), "load config by ARN")

	requireEqual(t, store.Get("Feature.Enabled"), true, "secret resolved by ARN")
}

// TestGasConfigProviderRejectsBadCredentials checks the provider cannot read
// secrets with the wrong access key, so a misconfigured app fails loudly.
func TestGasConfigProviderRejectsBadCredentials(t *testing.T) {
	srv := startServer(t, nil)
	createSecret(t, clientFor(srv), "example/guarded", `{"A":"b"}`)

	store := config.New(
		config.WithProvider(secretsmanager.NewProvider(
			secretsmanager.WithEndpoint(srv.URL),
			secretsmanager.WithRegion("us-east-1"),
			secretsmanager.WithStaticCredentials("wrong", "wrong"),
			secretsmanager.WithSecret("example/guarded"),
		)),
	)
	if err := store.Load(); err == nil {
		t.Fatal("want the load to fail with the wrong credentials, got nil")
	}
}

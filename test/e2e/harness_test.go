//go:build e2e

package e2e

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config/providers"

	"tule.dev/secret-store/internal/app"
)

// server is the app under test, served by the app's own *http.Server over a
// real TCP listener.
//
// The listener is created here rather than by gas.App.Serve, which calls
// ListenAndServe on the configured address and exposes neither the listener
// nor the port it ended up on. Everything else is the real thing: the server
// gas built from the bound configuration, with its timeouts, the CSRF wrapper
// and the router behind it, reached over the network and shut down through
// gas.App.Stop. Binding the configured port is left to the smoke test, which
// runs the built image as users do.
type server struct {
	app      *gas.App
	listener net.Listener
	client   *http.Client
	served   chan error
	URL      string
	Addr     string
	stopped  bool
}

// clientTimeout bounds a test's own requests, so a hung server fails the test
// instead of the suite's timeout. It is far longer than any server timeout
// under test.
const clientTimeout = 30 * time.Second

// newClient starts the app on a fresh store and returns an SDK client pointed
// at it.
func newClient(t *testing.T) *awssm.Client {
	t.Helper()
	return clientFor(startServer(t, nil))
}

// startServer starts the app on a fresh store, with env setting extra TULE_
// variables. It accepts the test/test credentials clientFor signs with unless
// env changes them.
func startServer(t *testing.T, env map[string]string) *server {
	t.Helper()

	setEnv(t, env)

	cfg, err := app.LoadConfigFrom(providers.NewEnvProvider(
		providers.WithEnvSeparator("_"),
		providers.WithEnvPrefix("TULE_"),
	))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	a, err := app.New(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	// Start binds the configuration into gas.Config and initializes the
	// services, so the server built after it carries the configured timeouts
	// rather than the gas defaults.
	if err = a.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}

	srv := serve(t, a)
	t.Cleanup(func() { srv.Stop(t) })
	return srv
}

func setEnv(t *testing.T, env map[string]string) {
	t.Helper()

	t.Setenv("TULE_GasEnv", "testing")
	t.Setenv("TULE_Store_RootDir", t.TempDir())
	t.Setenv("TULE_Auth_AccessKeyID", "test")
	t.Setenv("TULE_Auth_SecretAccessKey", "test")
	for k, v := range env {
		t.Setenv(k, v)
	}
}

// serve puts the app's own server on a loopback listener on a free port.
func serve(t *testing.T, a *gas.App) *server {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &server{
		app:      a,
		listener: listener,
		client:   &http.Client{Timeout: clientTimeout},
		served:   make(chan error, 1),
		Addr:     listener.Addr().String(),
		URL:      "http://" + listener.Addr().String(),
	}

	go func() {
		srv.served <- a.Server().Serve(listener)
	}()

	return srv
}

// Client returns an HTTP client for the server.
func (s *server) Client() *http.Client {
	return s.client
}

// Stop shuts the app down the way a signal does, through gas.App.Stop, and
// fails the test if the shutdown or the server itself reported an error. It
// is idempotent, so a test can stop the server early and let the cleanup run
// anyway.
func (s *server) Stop(t *testing.T) {
	t.Helper()

	if s.stopped {
		return
	}
	s.stopped = true

	if err := s.app.Stop(context.Background()); err != nil {
		t.Errorf("stop app: %v", err)
	}

	// A graceful shutdown ends Serve with ErrServerClosed; anything else is a
	// real failure.
	select {
	case err := <-s.served:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serve: %v", err)
		}
	case <-time.After(clientTimeout):
		t.Error("serve did not return after shutdown")
	}
}

// clientFor returns an SDK client for srv, with the test/test credentials
// unless opts change them.
func clientFor(srv *server, opts ...func(*awssm.Options)) *awssm.Client {
	return awssm.New(awssm.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(srv.URL),
		Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:   srv.Client(),
	}, opts...)
}

// startFailing loads the configuration and starts the app the way startServer
// does, returning the first error instead of failing the test, so a test can
// assert that a bad configuration keeps the app down.
func startFailing(t *testing.T) error {
	t.Helper()

	cfg, err := app.LoadConfigFrom(providers.NewEnvProvider(
		providers.WithEnvSeparator("_"),
		providers.WithEnvPrefix("TULE_"),
	))
	if err != nil {
		return err
	}

	a, err := app.New(cfg)
	if err != nil {
		return err
	}
	if err = a.Start(context.Background()); err != nil {
		return fmt.Errorf("start app: %w", err)
	}

	t.Cleanup(func() {
		if sErr := a.Shutdown(context.Background()); sErr != nil {
			t.Errorf("shutdown: %v", sErr)
		}
	})
	return nil
}

// createSecret creates a secret holding value and returns its ARN.
func createSecret(t *testing.T, c *awssm.Client, name, value string) string {
	t.Helper()

	out, err := c.CreateSecret(context.Background(), &awssm.CreateSecretInput{
		Name:         aws.String(name),
		SecretString: aws.String(value),
	})
	requireNoErr(t, err, "create secret "+name)

	return aws.ToString(out.ARN)
}

// getSecretString returns the AWSCURRENT secret string of name.
func getSecretString(t *testing.T, c *awssm.Client, name string) string {
	t.Helper()

	out, err := c.GetSecretValue(context.Background(), &awssm.GetSecretValueInput{
		SecretId: aws.String(name),
	})
	requireNoErr(t, err, "get secret value "+name)

	return aws.ToString(out.SecretString)
}

func requireNoErr(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func requireEqual[T comparable](t *testing.T, got, want T, what string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

// requireCode fails unless err is an API error with the given error code.
func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want API error %s, got %v", code, err)
	}
	if apiErr.ErrorCode() != code {
		t.Fatalf("want error code %s, got %s (%v)", code, apiErr.ErrorCode(), err)
	}
}

// requireAs fails unless err matches the modeled SDK error type T.
func requireAs[T error](t *testing.T, err error) {
	t.Helper()
	var want T
	if !errors.As(err, &want) {
		t.Fatalf("want error of type %T, got %v", want, err)
	}
}

// setTargetHeader replaces the operation header the SDK sends, which is the
// only way to ask this service for an operation no Secrets Manager client
// knows about. It runs before signing, so the request stays properly signed.
func setTargetHeader(target string) func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		return stack.Finalize.Add(middleware.FinalizeMiddlewareFunc(
			"e2eSetTargetHeader",
			func(
				ctx context.Context,
				in middleware.FinalizeInput,
				next middleware.FinalizeHandler,
			) (middleware.FinalizeOutput, middleware.Metadata, error) {
				if req, ok := in.Request.(*smithyhttp.Request); ok {
					req.Header.Set("X-Amz-Target", target)
				}
				return next.HandleFinalize(ctx, in)
			},
		), middleware.Before)
	}
}

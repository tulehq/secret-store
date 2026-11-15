package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/services/secrets/dirimpl"
)

func TestPortZeroIsAcceptedWithAFunctionsEndpoint(t *testing.T) {
	// The rotation service waits for gas's listening event, not for the
	// configured port, so a port the system picks is waited for as well.
	t.Setenv("TULE_Store_RootDir", t.TempDir())
	t.Setenv("TULE_Server_Port", "0")
	t.Setenv("TULE_Store_FunctionsEndpoint", "http://127.0.0.1:9060")
	cfg, err := loadEnvConfig(t, "AKID", "secret")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if _, err = New(cfg); err != nil {
		t.Fatalf("port 0 with a functions endpoint: %v", err)
	}
}

func TestRotationsWaitForTheListeningEvent(t *testing.T) {
	// The wait the rotation service runs before any step, as New builds
	// it; the rotation package's TestNoStepIsInvokedBeforeTheServerServes
	// covers that no step is invoked until it returns.
	t.Setenv("TULE_Store_RootDir", t.TempDir())
	t.Setenv("TULE_Server_Port", "0")
	t.Setenv("TULE_Store_FunctionsEndpoint", "http://127.0.0.1:9060")
	cfg, err := loadEnvConfig(t, "AKID", "secret")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	rs, err := newRotationSettings(a, cfg, &gas.NopLogger{})
	if err != nil {
		t.Fatalf("rotation settings: %v", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- rs.WaitServing(t.Context()) }()
	if err = a.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}

	select {
	case err = <-waited:
		t.Fatalf("returned after Start, before the server listened: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	serveLoopback(t, a)
	select {
	case err = <-waited:
		if err != nil {
			t.Fatalf("wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still waiting once the server listened")
	}
}

func TestAResumedRotationInvokesNothingBeforeTheServerListens(t *testing.T) {
	// The functions service is a recorder: the app under test is the one
	// New builds, with the wait it hands the rotation service.
	invoked := make(chan struct{})
	var once sync.Once
	functions := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(invoked) })
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(functions.Close)

	t.Setenv("TULE_Store_RootDir", t.TempDir())
	t.Setenv("TULE_Server_Port", "0")
	t.Setenv("TULE_Store_FunctionsEndpoint", functions.URL)
	cfg, err := loadEnvConfig(t, "AKID", "secret")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	seedRotationRun(t, cfg.Store)

	a, err := New(cfg)
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	if err = a.Start(context.Background()); err != nil {
		t.Fatalf("start app: %v", err)
	}

	select {
	case <-invoked:
		t.Fatal("the resumed rotation invoked its function before the server listened")
	case <-time.After(300 * time.Millisecond):
	}

	serveLoopback(t, a)
	select {
	case <-invoked:
	case <-time.After(10 * time.Second):
		t.Fatal("the resumed rotation invoked nothing once the server listened")
	}
}

// seedRotationRun leaves a rotation in progress in the store settings
// name, as a shutdown leaves one, for the next start to resume.
func seedRotationRun(t *testing.T, settings *dirimpl.Settings) {
	t.Helper()
	ctx := contracts.Unchecked(context.Background())
	store := dirimpl.NewService(settings)(&gas.NopLogger{})
	if err := store.Init(ctx); err != nil {
		t.Fatalf("init store: %v", err)
	}
	v := "v1"
	if _, err := store.CreateSecret(ctx, contracts.CreateSecretInput{
		Name: "app/db", Payload: contracts.Payload{String: &v},
	}); err != nil {
		t.Fatalf("create secret: %v", err)
	}
	if _, err := store.StartRotation(ctx, contracts.StartRotationInput{
		Now: time.Now(), SecretID: "app/db",
		LambdaARN: "arn:aws:lambda:us-east-1:000000000000:function:rotate",
	}); err != nil {
		t.Fatalf("start rotation: %v", err)
	}
	if err := store.Close(ctx); err != nil {
		t.Fatalf("close store: %v", err)
	}
}

// serveLoopback serves the started app a on a loopback listener on a free
// port, and stops it when the test ends.
func serveLoopback(t *testing.T, a *gas.App) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v (stop: %v)", err, a.Stop(context.Background()))
	}
	served := make(chan error, 1)
	go func() { served <- a.ServeListener(l) }()
	t.Cleanup(func() {
		if sErr := a.Stop(context.Background()); sErr != nil {
			t.Errorf("stop: %v", sErr)
		}
		if sErr := <-served; sErr != nil {
			t.Errorf("serve: %v", sErr)
		}
	})
}

func TestWaitListeningReturnsOnceListening(t *testing.T) {
	listening := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- waitListening(t.Context(), listening, &gas.NopLogger{}, time.Millisecond, time.Millisecond)
	}()
	select {
	case err := <-done:
		t.Fatalf("returned before the server listened: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(listening)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitListening: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waitListening did not return once the server listened")
	}
}

func TestWaitListeningReturnsWhenItsContextEnds(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	err := waitListening(ctx, make(chan struct{}), &gas.NopLogger{}, time.Hour, time.Hour)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitListening = %v, want the context's deadline", err)
	}
}

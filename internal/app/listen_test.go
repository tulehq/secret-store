package app

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/gasmod/gas"
)

func TestDialAddrMapsTheListenHost(t *testing.T) {
	tests := []struct{ host, want string }{
		{"", "127.0.0.1:9010"},
		{"0.0.0.0", "127.0.0.1:9010"},
		{"::", "[::1]:9010"},
		{"127.0.0.1", "127.0.0.1:9010"},
		{"192.168.65.254", "192.168.65.254:9010"},
		{"::1", "[::1]:9010"},
		{"secret-store.internal", "secret-store.internal:9010"},
	}
	for _, tt := range tests {
		got, err := dialAddr(tt.host, 9010)
		if err != nil || got != tt.want {
			t.Errorf("dialAddr(%q, 9010) = %q, %v; want %q", tt.host, got, err, tt.want)
		}
	}
}

func TestDialAddrRefusesPortZero(t *testing.T) {
	if _, err := dialAddr("0.0.0.0", 0); !errors.Is(err, errPortZero) {
		t.Fatalf("dialAddr with port 0 = %v, want errPortZero", err)
	}
}

func TestPortZeroIsRefusedOnlyWithAFunctionsEndpoint(t *testing.T) {
	t.Setenv("TULE_Store_RootDir", t.TempDir())
	t.Setenv("TULE_Server_Port", "0")
	cfg, err := loadEnvConfig(t, "AKID", "secret")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if _, err = New(cfg); err != nil {
		t.Fatalf("port 0 without a functions endpoint: %v", err)
	}

	t.Setenv("TULE_Store_FunctionsEndpoint", "http://127.0.0.1:9060")
	cfg, err = loadEnvConfig(t, "AKID", "secret")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if _, err = New(cfg); !errors.Is(err, errPortZero) {
		t.Fatalf("port 0 with a functions endpoint = %v, want errPortZero", err)
	}
}

func TestWaitListeningReturnsOnceTheServerAccepts(t *testing.T) {
	// A free port, which nothing listens on until the test does.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- waitListening(t.Context(), addr, &gas.NopLogger{}, time.Millisecond, time.Millisecond)
	}()
	select {
	case err = <-done:
		t.Fatalf("returned before anything listened: %v", err)
	case <-time.After(3 * listenPoll):
	}

	l, err = net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	select {
	case err = <-done:
		if err != nil {
			t.Fatalf("waitListening: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waitListening did not return once the server listened")
	}
}

func TestWaitListeningReturnsWhenItsContextEnds(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	err = waitListening(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		&gas.NopLogger{}, time.Hour, time.Hour)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitListening = %v, want the context's deadline", err)
	}
}

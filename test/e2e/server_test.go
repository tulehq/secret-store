//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// stallInBody writes a signed request whose headers are complete and whose
// body stops short of its Content-Length, so the server is still reading the
// body, under ReadTimeout and past ReadHeaderTimeout, when the test reads.
func stallInBody(t *testing.T, srv *server, conn net.Conn) {
	t.Helper()

	body := []byte(`{"Name":"example/stalled","SecretString":"placeholder"}`)
	if _, err := conn.Write(append(signedRequestBytes(t, srv, body), body[:20]...)); err != nil {
		t.Fatalf("write stalled request: %v", err)
	}
}

func TestServerTimeoutsAreInForce(t *testing.T) {
	srv := startServer(t, nil)

	// The timeouts are read off the server the app actually serves with, so
	// this fails if the configured values never reach it and the gas
	// defaults (5s read, 10s write) are what clients get.
	got := srv.app.Server()

	tests := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{name: "read", got: got.ReadTimeout, want: 30 * time.Second},
		{name: "read header", got: got.ReadHeaderTimeout, want: 30 * time.Second},
		{name: "write", got: got.WriteTimeout, want: 30 * time.Second},
		{name: "idle", got: got.IdleTimeout, want: 2 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s timeout = %s, want %s", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestReadTimeoutEndsAStalledRequest(t *testing.T) {
	srv := startServer(t, map[string]string{"TULE_Server_ReadTimeout": "300ms"})

	conn := dial(t, srv.Addr)
	stallInBody(t, srv, conn)

	// The server must give up on the stalled body. The signature check reads
	// the body, so it sees the read fail and answers with an error. Without a
	// read timeout in force this read blocks until the test's own deadline.
	start := time.Now()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if isTimeout(err) {
		t.Fatalf("the server held the stalled connection for %s", time.Since(start))
	}
	requireNoErr(t, err, "read the response to the stalled request")
	defer func() { _ = res.Body.Close() }()

	requireEqual(t, res.StatusCode, http.StatusBadRequest, "stalled request status")
	requireEqual(t, errorType(t, res.Body), "InvalidParameterException",
		"stalled request error type")
}

func TestALongReadTimeoutHoldsTheSameRequestOpen(t *testing.T) {
	// The counterpart to the test above: with a long read timeout the server
	// waits for the rest of the body, which is what shows the short timeout is doing the work there
	// and not something else closing connections.
	srv := startServer(t, map[string]string{"TULE_Server_ReadTimeout": "60s"})

	conn := dial(t, srv.Addr)
	stallInBody(t, srv, conn)

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	_, err := conn.Read(make([]byte, 1))
	if !isTimeout(err) {
		t.Fatalf("want the server to keep waiting, got %v", err)
	}
}

func TestShutdownClosesThePort(t *testing.T) {
	srv := startServer(t, nil)
	// One attempt, so the call after the shutdown fails at once instead of
	// retrying against a closed port with backoff.
	c := clientFor(srv, func(o *awssm.Options) { o.RetryMaxAttempts = 1 })

	createSecret(t, c, "example/shutdown", "v1")

	// Stop is what a SIGTERM runs: the server stops accepting, in-flight
	// requests finish, and then every service closes. Nothing is in flight
	// here, so this covers only the listener closing; the test below covers
	// a request that straddles the shutdown.
	srv.Stop(t)

	_, err := c.GetSecretValue(context.Background(), &awssm.GetSecretValueInput{
		SecretId: aws.String("example/shutdown"),
	})
	if err == nil {
		t.Fatal("want the port to refuse requests after shutdown, got a response")
	}

	if _, dErr := net.DialTimeout("tcp", srv.Addr, time.Second); dErr == nil {
		t.Fatal("want the listener closed after shutdown, got a connection")
	}
}

func TestShutdownWithAnUnusedConnectionIsClean(t *testing.T) {
	srv := startServer(t, nil)

	// A connection that is opened and never sent a request, as an SDK
	// client's spare one is. net/http counts it as idle, and closes it, only
	// 5s to 6s after it opened, so a shorter shutdown timeout runs out on it
	// and Stop reports the deadline, which fails the process on SIGTERM.
	dial(t, srv.Addr)
	time.Sleep(100 * time.Millisecond) // let the server accept it

	// Stop fails the test if App.Stop returns an error.
	srv.Stop(t)
}

func TestGracefulShutdownCompletesAnInFlightRequest(t *testing.T) {
	root := t.TempDir()
	srv := startServer(t, map[string]string{"TULE_Store_RootDir": root})

	// A CreateSecret whose body arrives in two pieces, so the handler is
	// blocked reading it when the shutdown starts. The whole body is signed,
	// so it has to arrive intact for the request to be served at all.
	body := []byte(`{"Name":"example/inflight","SecretString":"placeholder"}`)
	head, tail := body[:20], body[20:]

	conn := dial(t, srv.Addr)
	request := signedRequestBytes(t, srv, body)
	if _, err := conn.Write(append(request, head...)); err != nil {
		t.Fatalf("write request head: %v", err)
	}
	waitForHandler()

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		srv.Stop(t)
	}()
	waitForHandler()

	// The premise of the test: the shutdown is still waiting, because the
	// request it is waiting for has not been fully sent yet. Without this, a
	// request that finished before Stop ran would pass just as well.
	select {
	case <-stopped:
		t.Fatal("the shutdown finished before the in-flight request did")
	default:
	}

	if _, err := conn.Write(tail); err != nil {
		t.Fatalf("write request tail: %v", err)
	}

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	requireNoErr(t, err, "read the in-flight response")
	defer func() { _ = res.Body.Close() }()
	requireEqual(t, res.StatusCode, http.StatusOK, "in-flight request status")

	<-stopped

	// Reopened from a second app on the same directory, which is what the
	// next process to start would see: the write the shutdown waited for is
	// really on disk.
	reopened := clientFor(startServer(t, map[string]string{"TULE_Store_RootDir": root}))
	requireEqual(t, getSecretString(t, reopened, "example/inflight"), "placeholder",
		"value written by the in-flight request")
}

// waitForHandler gives the server a moment to reach the point the test is
// about: reading the body for the first wait, and starting the shutdown for
// the second. It is well inside the 7s shutdown timeout.
func waitForHandler() {
	time.Sleep(200 * time.Millisecond)
}

// signedRequestBytes returns the request line and headers of a signed
// CreateSecret call for body, ready to write to a raw connection. The body
// itself is written separately, in as many pieces as the test likes.
func signedRequestBytes(t *testing.T, srv *server, body []byte) []byte {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/", bytes.NewReader(body))
	requireNoErr(t, err, "build request")
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.CreateSecret")
	req.ContentLength = int64(len(body))

	sum := sha256.Sum256(body)
	creds := aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}
	err = v4.NewSigner().SignHTTP(context.Background(), creds, req,
		hex.EncodeToString(sum[:]), "secretsmanager", "us-east-1", time.Now())
	requireNoErr(t, err, "sign request")

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n",
		req.Host, len(body))
	for name, values := range req.Header {
		for _, value := range values {
			fmt.Fprintf(&buf, "%s: %s\r\n", name, value)
		}
	}
	buf.WriteString("\r\n")

	return buf.Bytes()
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// isTimeout reports whether err is the local read deadline expiring, as
// opposed to the server closing the connection.
func isTimeout(err error) bool {
	var netErr net.Error
	return err != nil && errors.As(err, &netErr) && netErr.Timeout()
}

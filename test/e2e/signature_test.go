//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// roundTripFunc is an http.RoundTripper made of a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// afterSigning returns a client option that has tamper change each request
// on its way out, after the SDK has signed it, as whoever relays a signed
// request could.
func afterSigning(t *testing.T, tamper func(*http.Request)) func(*awssm.Options) {
	t.Helper()

	// Its own transport, closed before the server stops, for the reason
	// server.Stop closes the server's client first.
	transport := &http.Transport{}
	t.Cleanup(transport.CloseIdleConnections)

	return func(o *awssm.Options) {
		o.RetryMaxAttempts = 1
		o.HTTPClient = &http.Client{
			Timeout: clientTimeout,
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				r = r.Clone(r.Context())
				tamper(r)
				return transport.RoundTrip(r)
			}),
		}
	}
}

func TestAnUnsignedAmzHeaderIsRefused(t *testing.T) {
	srv := startServer(t, nil)
	c := clientFor(srv)
	createSecret(t, c, "example/app", "placeholder")

	// A header that is not an x-amz-* one may be added in flight.
	_, err := c.GetSecretValue(context.Background(), &awssm.GetSecretValueInput{
		SecretId: aws.String("example/app"),
	}, afterSigning(t, func(r *http.Request) {
		r.Header.Set("X-Added", "added after signing")
	}))
	requireNoErr(t, err, "get with an unsigned plain header")

	// Every x-amz-* header must be signed, as AWS requires, so none can be
	// added to a signed request in flight.
	_, err = c.GetSecretValue(context.Background(), &awssm.GetSecretValueInput{
		SecretId: aws.String("example/app"),
	}, afterSigning(t, func(r *http.Request) {
		r.Header.Set("X-Amz-Injected", "added after signing")
	}))
	requireCode(t, err, "IncompleteSignatureException")
}

// rawRequest builds a GetSecretValue call for example/app, unsigned.
func rawRequest(t *testing.T, srv *server) (*http.Request, []byte) {
	t.Helper()

	body := []byte(`{"SecretId":"example/app"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/", bytes.NewReader(body))
	requireNoErr(t, err, "build request")
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	return req, body
}

// signRaw signs req with the test/test key for secretsmanager in us-east-1,
// listing signedHeaders exactly as given, as a hand-rolled client could, and
// signing each name as written: its value is req.Header.Values(name), or
// req.Host for "host". The SDK signer only writes canonical lists, so it
// cannot sign these.
func signRaw(t *testing.T, req *http.Request, body []byte, signedHeaders []string) {
	t.Helper()

	now := time.Now().UTC()
	date := now.Format("20060102")
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))

	var headers strings.Builder
	for _, name := range signedHeaders {
		value := strings.Join(req.Header.Values(name), ",")
		if name == "host" {
			value = req.Host
		}
		headers.WriteString(name + ":" + value + "\n")
	}
	list := strings.Join(signedHeaders, ";")
	bodyHash := sha256.Sum256(body)
	creq := strings.Join([]string{
		req.Method, "/", "", headers.String(), list, hex.EncodeToString(bodyHash[:]),
	}, "\n")

	scope := date + "/us-east-1/secretsmanager/aws4_request"
	creqHash := sha256.Sum256([]byte(creq))
	toSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", req.Header.Get("X-Amz-Date"), scope,
		hex.EncodeToString(creqHash[:]),
	}, "\n")

	key := []byte("AWS4test")
	for _, part := range []string{date, "us-east-1", "secretsmanager", "aws4_request"} {
		key = hmacSHA256(key, part)
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test/"+scope+
		", SignedHeaders="+list+", Signature="+hex.EncodeToString(hmacSHA256(key, toSign)))
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// sendRaw sends req and returns the response's status and error type, the
// latter empty on success.
func sendRaw(t *testing.T, srv *server, req *http.Request) (int, string) {
	t.Helper()

	res, err := srv.Client().Do(req)
	requireNoErr(t, err, "send request")
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode == http.StatusOK {
		return res.StatusCode, ""
	}
	return res.StatusCode, errorType(t, res.Body)
}

func TestASignedHeadersListMustBeCanonical(t *testing.T) {
	srv := startServer(t, nil)
	createSecret(t, clientFor(srv), "example/app", "placeholder")

	// The premise: the hand-rolled signer signs as the SDK does when given
	// the list the SDK would write.
	req, body := rawRequest(t, srv)
	signRaw(t, req, body, []string{"content-type", "host", "x-amz-date", "x-amz-target"})
	status, errType := sendRaw(t, srv, req)
	requireEqual(t, status, http.StatusOK, "canonical list status")

	for name, list := range map[string][]string{
		"repeated":  {"host", "x-amz-date", "x-amz-target", "x-amz-target"},
		"unsorted":  {"x-amz-date", "host", "x-amz-target"},
		"uppercase": {"host", "X-Amz-Date", "x-amz-target"},
		"spaced":    {"host", "x-amz-date", " x-amz-target", "x-amz-target"},
	} {
		t.Run(name, func(t *testing.T) {
			req, body := rawRequest(t, srv)
			signRaw(t, req, body, list)
			status, errType = sendRaw(t, srv, req)
			requireEqual(t, status, http.StatusForbidden, "status")
			requireEqual(t, errType, "IncompleteSignatureException", "error type")
		})
	}
}

func TestALargeRepeatedSignedHeadersListIsRefusedCheaply(t *testing.T) {
	srv := startServer(t, nil)

	// One 128 KiB header named 4096 times: canonicalized once per entry, the
	// canonical request would be 512 MiB, built before the signature is
	// compared. The list is refused before any of that, so the signature
	// itself need not be right.
	const repeats = 4096
	req, _ := rawRequest(t, srv)
	req.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
	req.Header.Set("X-Amz-Pad", strings.Repeat("a", 128<<10))
	list := "host;x-amz-date;" + strings.Repeat("x-amz-pad;", repeats) + "x-amz-target"
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test/"+
		time.Now().UTC().Format("20060102")+"/us-east-1/secretsmanager/aws4_request"+
		", SignedHeaders="+list+", Signature="+strings.Repeat("0", 64))

	// The server runs in this process, so what it allocates shows here.
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	status, errType := sendRaw(t, srv, req)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)

	requireEqual(t, status, http.StatusForbidden, "status")
	requireEqual(t, errType, "IncompleteSignatureException", "error type")
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 32<<20 {
		t.Fatalf("the request allocated %d MiB, want under 32", allocated>>20)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("the request took %s, want under 500ms", elapsed)
	}
}

func TestARequiredHeaderListedNonCanonicallyStaysBound(t *testing.T) {
	// A required header listed as " x-amz-target" or "Host" is not the
	// header sent, so the signature covers an empty value in its place and
	// the header could be changed in flight: a signed read relayed as a
	// delete, or a request signed for one host sent to another.
	tests := []struct {
		tamper        func(*http.Request)
		name          string
		signedHeaders []string
	}{
		{
			name:          "x-amz-target",
			signedHeaders: []string{"content-type", "host", "x-amz-date", " x-amz-target"},
			tamper: func(r *http.Request) {
				r.Header.Set("X-Amz-Target", "secretsmanager.DeleteSecret")
			},
		},
		{
			name:          "host",
			signedHeaders: []string{"Host", "content-type", "x-amz-date", "x-amz-target"},
			tamper:        func(r *http.Request) { r.Host = "elsewhere.example" },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, nil)
			c := clientFor(srv)
			createSecret(t, c, "example/app", "placeholder")

			req, body := rawRequest(t, srv)
			signRaw(t, req, body, tt.signedHeaders)
			tt.tamper(req)
			status, errType := sendRaw(t, srv, req)
			requireEqual(t, status, http.StatusForbidden, "status")
			requireEqual(t, errType, "IncompleteSignatureException", "error type")

			// Nothing was done in the request's name.
			requireEqual(t, getSecretString(t, c, "example/app"), "placeholder",
				"secret after the refused request")
		})
	}
}

func TestARequestSignedForAnotherServiceIsRefused(t *testing.T) {
	srv := startServer(t, nil)
	createSecret(t, clientFor(srv), "example/app", "placeholder")

	sign := func(service string) *http.Request {
		req, body := rawRequest(t, srv)
		sum := sha256.Sum256(body)
		creds := aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}
		requireNoErr(t, v4.NewSigner().SignHTTP(context.Background(), creds, req,
			hex.EncodeToString(sum[:]), service, "us-east-1", time.Now()),
			"sign request for "+service)
		return req
	}

	// The premise: the same request signed for secretsmanager is served.
	status, _ := sendRaw(t, srv, sign("secretsmanager"))
	requireEqual(t, status, http.StatusOK, "secretsmanager request status")

	status, errType := sendRaw(t, srv, sign("s3"))
	requireEqual(t, status, http.StatusForbidden, "s3 request status")
	requireEqual(t, errType, "InvalidSignatureException", "s3 request error type")
}

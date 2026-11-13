package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/smapi"
)

// keySourceFunc is a sigv4.KeySource made of a function.
type keySourceFunc func(context.Context, sigv4.Scope) (sigv4.Key, error)

func (f keySourceFunc) SigningKey(ctx context.Context, s sigv4.Scope) (sigv4.Key, error) {
	return f(ctx, s)
}

// signedRequest returns a GetSecretValue request signed with creds.
func signedRequest(t *testing.T, creds aws.Credentials) *http.Request {
	t.Helper()

	body := `{"SecretId":"example/app"}`
	req := httptest.NewRequest(http.MethodPost, "http://localhost:9010/",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	sum := sha256.Sum256([]byte(body))
	if err := v4.NewSigner().SignHTTP(t.Context(), creds, req, hex.EncodeToString(sum[:]),
		"secretsmanager", "us-east-1", time.Now()); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return req
}

// answer verifies req with v and returns the Secrets Manager error it is
// answered with, failing the test if it verifies.
func answer(t *testing.T, v *sigv4.Verifier, req *http.Request) *smapi.Error {
	t.Helper()

	_, err := v.Verify(req)
	if err == nil {
		t.Fatal("the request verified")
	}
	return smapi.ToError(t.Context(), err)
}

func TestWithoutAnIdentityEndpointTheConfiguredKeyIsTheOnlySource(t *testing.T) {
	keys, err := newKeySource(&authSettings{AccessKeyID: "AKID", SecretAccessKey: "secret"},
		"000000000000")
	if err != nil {
		t.Fatalf("new key source: %v", err)
	}
	if _, ok := keys.(*sigv4.StaticKey); !ok {
		t.Fatalf("key source = %T, want *sigv4.StaticKey", keys)
	}
}

func TestSessionTokenRefusalsAnswerAsAWSDoes(t *testing.T) {
	tests := []struct {
		refusal error
		errType string
		message string
	}{
		{
			refusal: sigv4.ErrInvalidSessionToken,
			errType: smapi.TypeUnrecognizedClient,
			message: "The security token included in the request is invalid.",
		},
		{
			refusal: sigv4.ErrExpiredSessionToken,
			errType: smapi.TypeExpiredToken,
			message: "The security token included in the request is expired",
		},
	}
	for _, tt := range tests {
		t.Run(tt.errType, func(t *testing.T) {
			// The source answers as identity's client does for a session key
			// whose token is not its own, or is past its expiration.
			v, err := verifierFor(keySourceFunc(
				func(context.Context, sigv4.Scope) (sigv4.Key, error) {
					return sigv4.Key{}, tt.refusal
				}))
			if err != nil {
				t.Fatalf("new verifier: %v", err)
			}
			got := answer(t, v, signedRequest(t, aws.Credentials{
				AccessKeyID:     "ASIAEXAMPLEEXAMPLE00",
				SecretAccessKey: "secret",
				SessionToken:    "token",
			}))
			want := smapi.Error{Status: http.StatusForbidden, Type: tt.errType, Message: tt.message}
			if *got != want {
				t.Fatalf("answered %+v, want %+v", *got, want)
			}
		})
	}
}

func TestAnUnreachableIdentityFailsClosed(t *testing.T) {
	// A port nothing listens on: identity is down.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	endpoint := "http://" + l.Addr().String()
	if err = l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	auth := &authSettings{
		AccessKeyID: "AKID", SecretAccessKey: "secret",
		IdentityEndpoint: endpoint,
	}
	v, err := newVerifier(auth, "000000000000")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	// A key only identity could know is neither refused as unknown nor
	// accepted: the lookup failed, which is the server's failure.
	got := answer(t, v, signedRequest(t, aws.Credentials{
		AccessKeyID:     "AKIAEXAMPLEEXAMPLE00",
		SecretAccessKey: "secret",
	}))
	if got.Status != http.StatusInternalServerError || got.Type != smapi.TypeInternalService {
		t.Fatalf("answered %d %s, want %d %s", got.Status, got.Type,
			http.StatusInternalServerError, smapi.TypeInternalService)
	}

	// The configured key is answered before identity is asked.
	if _, err = v.Verify(signedRequest(t, aws.Credentials{
		AccessKeyID:     "AKID",
		SecretAccessKey: "secret",
	})); err != nil {
		t.Fatalf("the configured key: %v", err)
	}
}

func TestAHungIdentityFailsClosed(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	saved := identityTimeout
	identityTimeout = 100 * time.Millisecond
	t.Cleanup(func() { identityTimeout = saved })

	v, err := newVerifier(&authSettings{
		AccessKeyID: "AKID", SecretAccessKey: "secret", IdentityEndpoint: srv.URL,
	}, "000000000000")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	// identity never answers: the lookup times out, which is the server's
	// failure, not an unknown key and not a success.
	start := time.Now()
	got := answer(t, v, signedRequest(t, aws.Credentials{
		AccessKeyID:     "AKIAEXAMPLEEXAMPLE00",
		SecretAccessKey: "secret",
	}))
	if got.Status != http.StatusInternalServerError || got.Type != smapi.TypeInternalService {
		t.Fatalf("answered %d %s, want %d %s", got.Status, got.Type,
			http.StatusInternalServerError, smapi.TypeInternalService)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the lookup took %v, want about the 100ms timeout", elapsed)
	}
}

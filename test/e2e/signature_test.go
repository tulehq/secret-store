//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
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

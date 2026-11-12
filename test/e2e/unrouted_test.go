//go:build e2e

package e2e

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// The router answers a request no route serves on its own. These answers are
// chi's, a plain-text 404 and an empty 405, and not an error document, so an
// SDK pointed at the wrong path reports a response it cannot decode, and one
// using the wrong method an UnknownError, rather than an error code this
// service never raises.

func TestUnroutedPathIsAPlainNotFound(t *testing.T) {
	srv := startServer(t, nil)
	c := clientFor(srv, func(o *awssm.Options) {
		o.BaseEndpoint = aws.String(srv.URL + "/nope")
		o.RetryMaxAttempts = 1
	})

	_, err := c.ListSecrets(context.Background(), &awssm.ListSecretsInput{})
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		t.Fatalf("want an undecodable response, got API error %s (%v)", apiErr.ErrorCode(), err)
	}
	header := requireResponse(t, err, http.StatusNotFound)
	requireEqual(t, header.Get("Content-Type"), "text/plain; charset=utf-8",
		"404 content type")
	requireEqual(t, header.Get("Cache-Control"), "", "404 cache control")
}

func TestWrongMethodIsAnEmptyMethodNotAllowed(t *testing.T) {
	srv := startServer(t, nil)
	c := clientFor(srv, func(o *awssm.Options) { o.RetryMaxAttempts = 1 })

	_, err := c.ListSecrets(context.Background(), &awssm.ListSecretsInput{},
		func(o *awssm.Options) {
			o.APIOptions = append(o.APIOptions, setMethod(http.MethodGet))
		})
	// An empty error body is what the SDK reads as UnknownError.
	requireCode(t, err, "UnknownError")
	header := requireResponse(t, err, http.StatusMethodNotAllowed)
	requireEqual(t, header.Get("Allow"), http.MethodPost, "405 Allow header")
	requireEqual(t, header.Get("Content-Type"), "", "405 content type")
	requireEqual(t, header.Get("Content-Length"), "0", "405 content length")
	requireEqual(t, header.Get("Cache-Control"), "", "405 cache control")
}

func TestUnknownMethodIsAnEmptyMethodNotAllowed(t *testing.T) {
	// The probes need no signature, so this reaches the router unsigned, as
	// any local process can. chi routes no such method, so it names no
	// method that would serve the path either.
	srv := startServer(t, nil)

	req, err := http.NewRequestWithContext(context.Background(), "FOO",
		srv.URL+"/_health", http.NoBody)
	requireNoErr(t, err, "build request")

	res, err := srv.Client().Do(req)
	requireNoErr(t, err, "unknown method")
	_ = res.Body.Close()

	requireEqual(t, res.StatusCode, http.StatusMethodNotAllowed, "unknown method status")
	requireEqual(t, res.Header.Get("Allow"), "", "unknown method Allow header")
	requireEqual(t, res.ContentLength, int64(0), "unknown method body length")
}

// requireResponse fails unless err reports an HTTP response with the given
// status, and returns that response's headers. The SDK has read and closed
// its body.
func requireResponse(t *testing.T, err error, status int) http.Header {
	t.Helper()

	var resErr *awshttp.ResponseError
	if !errors.As(err, &resErr) {
		t.Fatalf("want a response error, got %v", err)
	}
	requireEqual(t, resErr.HTTPStatusCode(), status, "status")

	return resErr.Response.Header
}

// setMethod replaces the method the SDK sends, which is always POST. It runs
// before signing, so the request stays properly signed.
func setMethod(method string) func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		return stack.Finalize.Add(middleware.FinalizeMiddlewareFunc(
			"e2eSetMethod",
			func(
				ctx context.Context,
				in middleware.FinalizeInput,
				next middleware.FinalizeHandler,
			) (middleware.FinalizeOutput, middleware.Metadata, error) {
				if req, ok := in.Request.(*smithyhttp.Request); ok {
					req.Method = method
				}
				return next.HandleFinalize(ctx, in)
			},
		), middleware.Before)
	}
}

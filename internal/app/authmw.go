package app

import (
	"fmt"
	"net/http"
	"time"

	"tule.dev/identity/keysource"
	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/modules/health"
	"tule.dev/secret-store/internal/smapi"
)

// maxRequestBody bounds the request body the verifier buffers to hash. The
// largest legitimate request is a secret value, which Secrets Manager caps at
// 64 KiB, so this leaves ample room for the JSON around one.
const maxRequestBody = 1 << 20

// identityTimeout bounds one call to identity's signing-key endpoint, so a
// hung identity fails the request it was verifying, as InternalServiceError,
// rather than holding it open.
const identityTimeout = 10 * time.Second

// newVerifier returns the SigV4 verifier for the configured access key and,
// when an identity endpoint is configured, every key identity issued.
func newVerifier(auth *authSettings, accountID string) (*sigv4.Verifier, error) {
	keys, err := newKeySource(auth, accountID)
	if err != nil {
		return nil, fmt.Errorf("signature verifier: %w", err)
	}
	return verifierFor(keys)
}

// newKeySource returns the configured key alone when no identity endpoint is
// set. Otherwise it asks the configured key first and identity for any other
// key ID, signing its calls to identity with the configured key, which must
// therefore be identity's root key.
//
// identity's answer is final: an unknown, inactive or deleted key and a bad
// or expired session token are refused as AWS refuses them, and identity
// failing or being unreachable is a key lookup failure, which signatureError
// leaves to be answered InternalServiceError. Neither is ever a success.
func newKeySource(auth *authSettings, accountID string) (sigv4.KeySource, error) {
	static, err := sigv4.NewStaticKey(sigv4.StaticKeyConfig{
		AccessKeyID:     auth.AccessKeyID,
		SecretAccessKey: auth.SecretAccessKey,
		AccountID:       accountID,
	})
	if err != nil {
		return nil, fmt.Errorf("static key: %w", err)
	}
	if auth.IdentityEndpoint == "" {
		return static, nil
	}
	identity, err := keysource.New(keysource.Config{
		HTTPClient:      &http.Client{Timeout: identityTimeout},
		Endpoint:        auth.IdentityEndpoint,
		AccessKeyID:     auth.AccessKeyID,
		SecretAccessKey: auth.SecretAccessKey,
	})
	if err != nil {
		return nil, fmt.Errorf("identity key source: %w", err)
	}
	return sigv4.Chain(static, identity), nil
}

// verifierFor returns the SigV4 verifier over keys.
//
// Secrets Manager speaks the AWS JSON protocol: every request is a POST with
// a small JSON body and an Authorization header, so there are no presigned
// URLs or streamed payloads. The SDK signs the payload hash without sending
// it, so the body is buffered and hashed, and the handler reads that buffer.
// The signature must cover X-Amz-Target as well as Host and X-Amz-Date: it
// names the operation, and left unsigned it would let whoever relays a signed
// read turn it into a delete, since the two carry the same body.
// The credential must be scoped to secretsmanager, so a signature made for
// another service is not one for this one. Its region is not checked: the
// configured region only appears in the ARNs the store mints.
func verifierFor(keys sigv4.KeySource) (*sigv4.Verifier, error) {
	v, err := sigv4.New(
		keys,
		sigv4.WithBufferedPayload(maxRequestBody),
		sigv4.WithRequiredSignedHeaders("host", "x-amz-date", "x-amz-target"),
		sigv4.WithService("secretsmanager"),
		sigv4.WithErrorMap(signatureError),
	)
	if err != nil {
		return nil, fmt.Errorf("signature verifier: %w", err)
	}
	return v, nil
}

// verifySignature rejects requests whose SigV4 signature does not verify
// against v, and serves the rest as Verify returns them: with the body the
// signature covered and the signer in the context.
//
// The health probes are exempt, so a container's health check needs no
// credentials; nothing else is, because any web page the developer has open
// can reach a server on localhost, and this one serves secrets.
func verifySignature(v *sigv4.Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isProbe(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			verified, err := v.Verify(r)
			if err != nil {
				smapi.WriteHTTPError(w, r, err)
				return
			}
			next.ServeHTTP(w, verified)
		})
	}
}

func isProbe(path string) bool {
	return path == health.HealthPath || path == health.ReadyPath
}

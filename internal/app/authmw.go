package app

import (
	"fmt"
	"net/http"

	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/modules/health"
	"tule.dev/secret-store/internal/smapi"
)

// maxRequestBody bounds the request body the verifier buffers to hash. The
// largest legitimate request is a secret value, which Secrets Manager caps at
// 64 KiB, so this leaves ample room for the JSON around one.
const maxRequestBody = 1 << 20

// newVerifier returns the SigV4 verifier for the one configured access key.
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
func newVerifier(auth *authSettings, accountID string) (*sigv4.Verifier, error) {
	keys, err := sigv4.NewStaticKey(sigv4.StaticKeyConfig{
		AccessKeyID:     auth.AccessKeyID,
		SecretAccessKey: auth.SecretAccessKey,
		AccountID:       accountID,
	})
	if err != nil {
		return nil, fmt.Errorf("signature verifier: %w", err)
	}
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

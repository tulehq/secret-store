package app

import (
	"net/http"

	"tule.dev/secret-store/internal/modules/health"
	"tule.dev/secret-store/internal/sigv4"
	"tule.dev/secret-store/internal/smapi"
)

// verifySignature rejects requests whose SigV4 signature does not verify
// against v.
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
			if err := v.Verify(r); err != nil {
				smapi.WriteHTTPError(w, r, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isProbe(path string) bool {
	return path == health.HealthPath || path == health.ReadyPath
}

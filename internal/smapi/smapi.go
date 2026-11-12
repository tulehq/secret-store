// Package smapi is the Secrets Manager wire layer: the AWS JSON 1.1 envelope
// the SDK speaks, the operation targets, the request and response shapes, and
// the error documents.
//
// AWS calls the service Secrets Manager and its SDK package
// "secretsmanager"; this service is secret-store, so the wire details live
// here rather than spelling the AWS name into the store or the modules.
package smapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/httpx"
)

// ContentType is the media type of every request and response body: Secrets
// Manager speaks the AWS JSON 1.1 protocol.
const ContentType = "application/x-amz-json-1.1"

// targetPrefix is what the SDK puts before the operation name in X-Amz-Target.
const targetPrefix = "secretsmanager."

// TargetHeader carries the operation name of a request.
const TargetHeader = "X-Amz-Target"

// requestIDHeader is where AWS reports the ID of a request, which clients
// quote in bug reports.
const requestIDHeader = "X-Amzn-Requestid"

// Operation returns the operation an X-Amz-Target header names, or "" when the
// header is not exactly the target prefix followed by a name. The dispatcher
// then decides whether the name is an operation this service serves.
func Operation(header string) string {
	op, ok := strings.CutPrefix(header, targetPrefix)
	if !ok {
		return ""
	}
	return op
}

// Write sends v as the AWS JSON 1.1 body of a successful response.
func Write(ctx gas.Context, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return WriteError(ctx, err)
	}

	w := ctx.ResponseWriter()
	w.Header().Set("Content-Type", ContentType)
	setRequestID(w, ctx.Request())
	w.WriteHeader(http.StatusOK)

	if _, wErr := w.Write(body); wErr != nil {
		httpx.Logger(ctx).Warn("failed to write response").Err("error", wErr).Send()
	}
	return nil
}

func setRequestID(w http.ResponseWriter, r *http.Request) {
	if id := httpx.RequestIDOf(r.Context()); id != "" {
		w.Header().Set(requestIDHeader, id)
	}
}

// Package secret serves the Secrets Manager API: one route that dispatches on
// the operation named in the request's X-Amz-Target header, as the AWS JSON
// protocol does.
package secret

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/smapi"
)

const moduleName = "tule/modules/secret"

// Module registers the API route and serves the operations behind it.
type Module struct {
	router   *gas.Router
	logger   gas.Logger
	secrets  contracts.SecretsProvider
	handlers map[string]handler
}

// handler serves one operation. Returning an error leaves the response to the
// dispatcher, which renders it as a Secrets Manager error document.
type handler func(gas.Context) error

// NewModule returns a Module serving from secrets. It registers its route when
// the app initializes it.
func NewModule(
	router *gas.Router,
	logger gas.Logger,
	secrets contracts.SecretsProvider,
) *Module {
	m := &Module{
		router:  router,
		logger:  logger.With().Str("module", moduleName).Logger(),
		secrets: secrets,
	}
	m.handlers = map[string]handler{
		"BatchGetSecretValue":      m.batchGetSecretValue,
		"CreateSecret":             m.createSecret,
		"DeleteSecret":             m.deleteSecret,
		"DescribeSecret":           m.describeSecret,
		"GetSecretValue":           m.getSecretValue,
		"ListSecretVersionIds":     m.listSecretVersionIDs,
		"ListSecrets":              m.listSecrets,
		"PutSecretValue":           m.putSecretValue,
		"RestoreSecret":            m.restoreSecret,
		"TagResource":              m.tagResource,
		"UntagResource":            m.untagResource,
		"UpdateSecret":             m.updateSecret,
		"UpdateSecretVersionStage": m.updateSecretVersionStage,
	}
	return m
}

// unserved are the Secrets Manager operations this service knows of and
// answers with 501. Most of them need something a local stand-in has no
// business faking -- KMS, Lambda rotation, IAM policy evaluation or
// cross-region replication -- and GetRandomPassword is left out because
// standing in for Secrets Manager does not require inventing passwords.
var unserved = []string{
	"CancelRotateSecret",
	"DeleteResourcePolicy",
	"GetRandomPassword",
	"GetResourcePolicy",
	"PutResourcePolicy",
	"RemoveRegionsFromReplication",
	"ReplicateSecretToRegions",
	"RotateSecret",
	"StopReplicationToReplica",
	"ValidateResourcePolicy",
}

// Name identifies the module to gas.
func (m *Module) Name() string {
	return moduleName
}

// Init registers the module's route.
func (m *Module) Init(context.Context) error {
	// The AWS JSON protocol puts every operation on POST /, so there is one
	// route and the operation comes from a header.
	m.router.Handle(m, http.MethodPost, "/", m.dispatch)
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error {
	return nil
}

func (m *Module) dispatch(ctx gas.Context) error {
	op := smapi.Operation(ctx.Header(smapi.TargetHeader))

	h, ok := m.handlers[op]
	switch {
	case ok:
		if err := h(ctx); err != nil {
			return smapi.WriteError(ctx, err)
		}
		return nil
	case slices.Contains(unserved, op):
		return smapi.WriteError(ctx, smapi.ErrNotImplemented(
			op+" is not implemented by this service."))
	default:
		return smapi.WriteError(ctx, smapi.ErrUnknownOperation(
			"The X-Amz-Target header names no Secrets Manager operation this service serves."))
	}
}

// decode reads a request body into T. An empty body decodes to the zero value,
// and unknown fields are ignored, as the AWS JSON protocol expects.
func decode[T any](ctx gas.Context) (T, error) {
	var body T
	err := json.NewDecoder(ctx.Request().Body).Decode(&body)
	if err != nil && !errors.Is(err, io.EOF) {
		return body, smapi.ErrSerialization("The request body is not valid JSON.")
	}
	return body, nil
}

// payloadOf builds the value a write stores from the two fields that may carry
// one.
func payloadOf(secretString *string, secretBinary []byte) contracts.Payload {
	return contracts.Payload{String: secretString, Binary: secretBinary}
}

// requireSecretID rejects a request that names no secret. The SDKs check this
// themselves, so it only catches hand-built requests.
func requireSecretID(secretID string) error {
	if secretID == "" {
		return smapi.ErrInvalidParameter("SecretId is required.")
	}
	return nil
}

// rejectFilters refuses the filters the list operations accept, which this
// service does not evaluate. Answering with everything instead would look
// like a filter that matches too much.
func rejectFilters(filters []smapi.Filter) error {
	if len(filters) == 0 {
		return nil
	}
	return smapi.ErrInvalidParameter(
		"Filters are not supported by this service; list without them and filter client-side.")
}

// rejectSort refuses a requested order, for the same reason as rejectFilters:
// listings are always in name order, and silently serving another order is
// worse than saying so.
func rejectSort(sortBy, sortOrder string) error {
	if sortBy == "" && sortOrder == "" {
		return nil
	}
	return smapi.ErrInvalidParameter(
		"SortBy and SortOrder are not supported by this service; secrets are listed by name.")
}

func tagsOf(tags []smapi.Tag) []contracts.Tag {
	out := make([]contracts.Tag, 0, len(tags))
	for _, t := range tags {
		out = append(out, contracts.Tag{Key: t.Key, Value: t.Value})
	}
	return out
}

func wireTags(tags []contracts.Tag) []smapi.Tag {
	if len(tags) == 0 {
		return nil
	}
	out := make([]smapi.Tag, 0, len(tags))
	for _, t := range tags {
		out = append(out, smapi.Tag{Key: t.Key, Value: t.Value})
	}
	return out
}

func secretRef(ref contracts.SecretRef) smapi.SecretRefResponse {
	return smapi.SecretRefResponse{ARN: ref.ARN, Name: ref.Name}
}

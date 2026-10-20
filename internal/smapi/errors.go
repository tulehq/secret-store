package smapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/httpx"
)

// errorTypeHeader is the error code clients that do not read the body look
// for. Secrets Manager carries the code in the body's __type, and the SDK
// reads either, so both are sent.
const errorTypeHeader = "X-Amzn-Errortype"

// Error is a Secrets Manager error document. It implements error so handlers
// and the store can return one directly for conditions that have no
// store-layer sentinel.
type Error struct {
	Type    string `json:"__type"`
	Message string `json:"Message"`
	Status  int    `json:"-"`
}

func (e *Error) Error() string {
	return e.Type + ": " + e.Message
}

// NewError builds an error document with the given status and type.
func NewError(status int, errType, message string) *Error {
	return &Error{Status: status, Type: errType, Message: message}
}

// The Secrets Manager error types this service raises. Every modeled client
// error is a 400 in the AWS JSON protocol, whatever it is about.
const (
	TypeResourceNotFound   = "ResourceNotFoundException"
	TypeResourceExists     = "ResourceExistsException"
	TypeInvalidParameter   = "InvalidParameterException"
	TypeInvalidRequest     = "InvalidRequestException"
	TypeInvalidNextToken   = "InvalidNextTokenException"
	TypeLimitExceeded      = "LimitExceededException"
	TypeInternalService    = "InternalServiceError"
	TypeUnknownOperation   = "UnknownOperationException"
	TypeSerialization      = "SerializationException"
	TypeNotImplemented     = "NotImplementedException"
	TypeMissingAuthToken   = "MissingAuthenticationTokenException"
	TypeIncompleteSig      = "IncompleteSignatureException"
	TypeInvalidSignature   = "InvalidSignatureException"
	TypeUnrecognizedClient = "UnrecognizedClientException"
)

// ErrResourceNotFound is the error for an identifier that names no secret.
func ErrResourceNotFound(msg string) *Error {
	return NewError(http.StatusBadRequest, TypeResourceNotFound, msg)
}

// ErrInvalidParameter is the error for a parameter whose value is not allowed.
func ErrInvalidParameter(msg string) *Error {
	return NewError(http.StatusBadRequest, TypeInvalidParameter, msg)
}

// ErrInvalidRequest is the error for a request that is well-formed but cannot
// be served in the secret's current state.
func ErrInvalidRequest(msg string) *Error {
	return NewError(http.StatusBadRequest, TypeInvalidRequest, msg)
}

// ErrSerialization is the error for a body that is not valid JSON.
func ErrSerialization(msg string) *Error {
	return NewError(http.StatusBadRequest, TypeSerialization, msg)
}

// ErrUnknownOperation is the error for an X-Amz-Target this service does not
// recognize at all.
func ErrUnknownOperation(msg string) *Error {
	return NewError(http.StatusBadRequest, TypeUnknownOperation, msg)
}

// ErrNotImplemented is the error for a Secrets Manager operation this service
// knows of but does not serve. It is a 501 rather than one of the modeled
// client errors, so a caller can tell "this stand-in does not do that" from
// "your request was wrong".
func ErrNotImplemented(msg string) *Error {
	return NewError(http.StatusNotImplemented, TypeNotImplemented, msg)
}

// ErrInternalService is the error every unrecognized failure becomes.
func ErrInternalService() *Error {
	return NewError(http.StatusInternalServerError, TypeInternalService,
		"An error occurred on the server side.")
}

// sentinelErrors maps store-layer sentinels to the errors they become.
var sentinelErrors = []struct {
	err    error
	apiErr *Error
}{
	{
		contracts.ErrSecretNotFound,
		ErrResourceNotFound("Secrets Manager can't find the specified secret."),
	},
	{contracts.ErrVersionNotFound, ErrResourceNotFound(
		"Secrets Manager can't find the specified secret value for the requested " +
			"version ID or staging label.")},
	{contracts.ErrSecretExists, NewError(http.StatusBadRequest, TypeResourceExists,
		"The operation failed because the secret already exists.")},
	{contracts.ErrVersionExists, NewError(http.StatusBadRequest, TypeResourceExists,
		"A version with this client request token already exists and holds a different value.")},
	{contracts.ErrSecretDeleted, ErrInvalidRequest(
		"You can't perform this operation on the secret because it was marked for deletion.")},
	{contracts.ErrSecretNotDeleted, ErrInvalidRequest(
		"You can't restore this secret because it is not marked for deletion.")},
	{contracts.ErrInvalidName, ErrInvalidParameter(
		"Invalid name. Must be a valid name containing alphanumeric characters, " +
			"or any of the following: -/_+=.@!")},
	{contracts.ErrInvalidValue, ErrInvalidParameter(
		"You must provide either SecretString or SecretBinary, but not both.")},
	{contracts.ErrStageMismatch, ErrInvalidRequest(
		"The staging label you are trying to move is not attached to the version " +
			"you are trying to move it from.")},
	{contracts.ErrStageAttached, ErrInvalidRequest(
		"The staging label is attached to another version of this secret. Specify " +
			"RemoveFromVersionId with the version it should be removed from.")},
	{contracts.ErrCurrentStageRequired, ErrInvalidParameter(
		"You can't remove the AWSCURRENT staging label from a version without moving " +
			"it to another version, which would leave the secret with no current value.")},
	{contracts.ErrValueTooLarge, ErrInvalidParameter(
		"The secret value must be 65536 bytes or fewer.")},
	{contracts.ErrInvalidToken, NewError(http.StatusBadRequest, TypeInvalidNextToken,
		"Invalid NextToken.")},
}

// ToError maps err to an error document, logging it when it maps to an
// internal error. It returns a copy, safe for the caller to fill in.
func ToError(ctx context.Context, err error) *Error {
	apiErr := toAPIError(err)
	if apiErr.Status == http.StatusInternalServerError {
		httpx.Logger(ctx).Error("request failed").Err("error", err).Send()
	}
	return apiErr
}

func toAPIError(err error) *Error {
	var apiErr *Error
	if errors.As(err, &apiErr) {
		cp := *apiErr
		return &cp
	}

	for _, se := range sentinelErrors {
		if errors.Is(err, se.err) {
			cp := *se.apiErr
			return &cp
		}
	}

	return ErrInternalService()
}

// WriteError renders err as a Secrets Manager error response.
func WriteError(ctx gas.Context, err error) error {
	writeError(ctx.ResponseWriter(), ctx.Request(), err)
	return nil
}

// WriteHTTPError is WriteError for plain http.Handler middleware, which has no
// gas.Context.
func WriteHTTPError(w http.ResponseWriter, r *http.Request, err error) {
	writeError(w, r, err)
}

func writeError(w http.ResponseWriter, r *http.Request, err error) {
	apiErr := ToError(r.Context(), err)

	body, mErr := json.Marshal(apiErr)
	if mErr != nil {
		httpx.Logger(r.Context()).Error("failed to encode error response").
			Err("error", mErr).Send()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentType)
	w.Header().Set(errorTypeHeader, apiErr.Type)
	setRequestID(w, r)
	w.WriteHeader(apiErr.Status)

	if _, wErr := w.Write(body); wErr != nil {
		httpx.Logger(r.Context()).Warn("failed to write error response").
			Err("error", wErr).Send()
	}
}

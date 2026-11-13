package app

import (
	"errors"
	"net/http"
	"testing"

	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/smapi"
)

func TestSignatureErrorAnswersEachKindAsSecretsManagerDoes(t *testing.T) {
	const msg = "the verifier's message"

	tests := []struct {
		errType string
		kind    sigv4.Kind
		status  int
	}{
		{smapi.TypeMissingAuthToken, sigv4.KindMissingAuth, http.StatusForbidden},
		{smapi.TypeIncompleteSig, sigv4.KindUnsupportedAlgorithm, http.StatusForbidden},
		{smapi.TypeIncompleteSig, sigv4.KindIncompleteAuth, http.StatusForbidden},
		{smapi.TypeIncompleteSig, sigv4.KindInvalidDate, http.StatusForbidden},
		{smapi.TypeIncompleteSig, sigv4.KindUnsignedHeader, http.StatusForbidden},
		{smapi.TypeIncompleteSig, sigv4.KindMalformedCredential, http.StatusForbidden},
		{smapi.TypeIncompleteSig, sigv4.KindCredentialDateMismatch, http.StatusForbidden},
		{smapi.TypeIncompleteSig, sigv4.KindPayloadHashNotAccepted, http.StatusForbidden},
		{smapi.TypeInvalidSignature, sigv4.KindRequestTimeTooSkewed, http.StatusForbidden},
		{smapi.TypeInvalidSignature, sigv4.KindSignatureMismatch, http.StatusForbidden},
		{smapi.TypeInvalidSignature, sigv4.KindWrongService, http.StatusForbidden},
		{smapi.TypeUnrecognizedClient, sigv4.KindUnknownAccessKey, http.StatusForbidden},
		{smapi.TypeUnrecognizedClient, sigv4.KindInvalidSessionToken, http.StatusForbidden},
		{smapi.TypeExpiredToken, sigv4.KindExpiredSessionToken, http.StatusForbidden},
		{smapi.TypeInvalidParameter, sigv4.KindPayloadHashMismatch, http.StatusBadRequest},
		{smapi.TypeInvalidParameter, sigv4.KindBodyUnreadable, http.StatusBadRequest},
		{
			smapi.TypeInvalidParameter, sigv4.KindBodyTooLarge,
			http.StatusRequestEntityTooLarge,
		},
	}
	for _, tt := range tests {
		t.Run(tt.kind.String(), func(t *testing.T) {
			err := signatureError(&sigv4.Error{Kind: tt.kind, Message: msg})

			var apiErr *smapi.Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("error = %v, want an *smapi.Error", err)
			}
			want := smapi.Error{Status: tt.status, Type: tt.errType, Message: msg}
			if *apiErr != want {
				t.Fatalf("error = %+v, want %+v", *apiErr, want)
			}
		})
	}
}

func TestSignatureErrorLeavesAKeyLookupFailureInternal(t *testing.T) {
	// A KeySource failure is no client error: it reaches smapi as the
	// verifier's own error, which smapi logs and answers InternalServiceError.
	e := &sigv4.Error{Kind: sigv4.KindKeyLookupFailed, Message: "lookup failed"}
	err := signatureError(e)
	if !errors.Is(err, e) {
		t.Fatalf("error = %v, want the verifier's own error", err)
	}
	if got := smapi.ToError(t.Context(), err); got.Type != smapi.TypeInternalService {
		t.Fatalf("answered as %s, want %s", got.Type, smapi.TypeInternalService)
	}
}

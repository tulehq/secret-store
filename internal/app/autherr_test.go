package app

import (
	"errors"
	"net/http"
	"testing"

	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/smapi"
)

// mappedKinds are the Kinds signatureError answers as client errors, with
// the Secrets Manager error each becomes.
var mappedKinds = []struct {
	errType string
	kind    sigv4.Kind
	status  int
}{
	{smapi.TypeMissingAuthToken, sigv4.KindMissingAuth, http.StatusForbidden},
	{smapi.TypeIncompleteSig, sigv4.KindUnsupportedAlgorithm, http.StatusBadRequest},
	{smapi.TypeIncompleteSig, sigv4.KindIncompleteAuth, http.StatusBadRequest},
	{smapi.TypeIncompleteSig, sigv4.KindInvalidDate, http.StatusBadRequest},
	{smapi.TypeIncompleteSig, sigv4.KindUnsignedHeader, http.StatusBadRequest},
	{smapi.TypeIncompleteSig, sigv4.KindMalformedCredential, http.StatusBadRequest},
	{smapi.TypeIncompleteSig, sigv4.KindCredentialDateMismatch, http.StatusBadRequest},
	{smapi.TypeIncompleteSig, sigv4.KindPayloadHashNotAccepted, http.StatusBadRequest},
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

func TestSignatureErrorAnswersEachKindAsSecretsManagerDoes(t *testing.T) {
	const msg = "the verifier's message"

	for _, tt := range mappedKinds {
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

func TestSignatureErrorFailsEveryOtherKindClosed(t *testing.T) {
	// A Kind the map does not name, the key lookup failing, those this
	// configuration cannot produce, and any a later sigv4 adds, comes back as
	// the verifier's own error, which smapi logs and answers
	// InternalServiceError: never a success, and never a client error it
	// was not meant to be.
	mapped := make(map[sigv4.Kind]bool, len(mappedKinds))
	for _, m := range mappedKinds {
		mapped[m.kind] = true
	}
	for kind := sigv4.KindMissingAuth; kind <= sigv4.KindSignatureMismatch+1; kind++ {
		if mapped[kind] {
			continue
		}
		t.Run(kind.String(), func(t *testing.T) {
			e := &sigv4.Error{Kind: kind, Message: "the verifier's message"}
			err := signatureError(e)

			var got *sigv4.Error
			if !errors.As(err, &got) || got != e {
				t.Fatalf("error = %v, want the verifier's own error", err)
			}
			apiErr := smapi.ToError(t.Context(), err)
			if apiErr.Status != http.StatusInternalServerError ||
				apiErr.Type != smapi.TypeInternalService {
				t.Fatalf("answered as %d %s, want %d %s", apiErr.Status, apiErr.Type,
					http.StatusInternalServerError, smapi.TypeInternalService)
			}
		})
	}
}

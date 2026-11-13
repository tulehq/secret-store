package app

import (
	"net/http"

	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/smapi"
)

// signatureError maps a verification failure to the Secrets Manager error
// this service answers it with, keeping the verifier's message.
//
// A Kind this verifier is not configured to produce, or a failure of the key
// lookup itself, is returned as is: smapi.WriteHTTPError logs it and answers
// InternalServiceError, as it does every error it does not recognize.
func signatureError(e *sigv4.Error) error {
	switch e.Kind {
	case sigv4.KindMissingAuth:
		return smapi.NewError(http.StatusForbidden, smapi.TypeMissingAuthToken, e.Message)
	case sigv4.KindUnsupportedAlgorithm, sigv4.KindIncompleteAuth, sigv4.KindInvalidDate,
		sigv4.KindUnsignedHeader, sigv4.KindMalformedCredential,
		sigv4.KindCredentialDateMismatch, sigv4.KindPayloadHashNotAccepted:
		return smapi.NewError(http.StatusForbidden, smapi.TypeIncompleteSig, e.Message)
	case sigv4.KindRequestTimeTooSkewed, sigv4.KindSignatureMismatch:
		return smapi.NewError(http.StatusForbidden, smapi.TypeInvalidSignature, e.Message)
	case sigv4.KindUnknownAccessKey, sigv4.KindInvalidSessionToken:
		return smapi.NewError(http.StatusForbidden, smapi.TypeUnrecognizedClient, e.Message)
	case sigv4.KindExpiredSessionToken:
		return smapi.NewError(http.StatusForbidden, smapi.TypeExpiredToken, e.Message)
	case sigv4.KindPayloadHashMismatch, sigv4.KindBodyUnreadable:
		return smapi.ErrInvalidParameter(e.Message)
	case sigv4.KindBodyTooLarge:
		return smapi.NewError(http.StatusRequestEntityTooLarge, smapi.TypeInvalidParameter,
			e.Message)
	default:
		return e
	}
}

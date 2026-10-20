package smapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"tule.dev/secret-store/internal/contracts"
)

var errUnmapped = errors.New("something the store did not model")

func TestOperation(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{name: "SDK target", header: "secretsmanager.GetSecretValue", want: "GetSecretValue"},
		{name: "bare operation", header: "GetSecretValue", want: "GetSecretValue"},
		{name: "empty", header: "", want: ""},
		{name: "prefix only", header: "secretsmanager.", want: ""},
		{name: "another service", header: "s3.GetObject", want: ""},
		{name: "shape ID", header: "com.amazonaws#GetSecretValue", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Operation(tt.header); got != tt.want {
				t.Fatalf("Operation(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestTimestampMarshalsAsEpochSeconds(t *testing.T) {
	// The AWS JSON protocol puts a time on the wire as epoch seconds, so a
	// string here would be silently unparseable to every SDK.
	ts := Timestamp(time.Date(2026, time.January, 2, 3, 4, 5, 500*int(time.Millisecond),
		time.UTC))

	got, err := json.Marshal(ts)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := "1767323045.5"; string(got) != want {
		t.Fatalf("marshal = %s, want %s", got, want)
	}
}

func TestStampOmitsTheZeroTime(t *testing.T) {
	if Stamp(time.Time{}) != nil {
		t.Fatal("Stamp of the zero time is not nil")
	}
	if Stamp(time.Now()) == nil {
		t.Fatal("Stamp of a real time is nil")
	}
}

func TestToErrorMapsStoreSentinels(t *testing.T) {
	tests := []struct {
		err        error
		wantType   string
		wantStatus int
	}{
		{contracts.ErrSecretNotFound, TypeResourceNotFound, http.StatusBadRequest},
		{contracts.ErrVersionNotFound, TypeResourceNotFound, http.StatusBadRequest},
		{contracts.ErrSecretExists, TypeResourceExists, http.StatusBadRequest},
		{contracts.ErrVersionExists, TypeResourceExists, http.StatusBadRequest},
		{contracts.ErrSecretDeleted, TypeInvalidRequest, http.StatusBadRequest},
		{contracts.ErrSecretNotDeleted, TypeInvalidRequest, http.StatusBadRequest},
		{contracts.ErrStageMismatch, TypeInvalidRequest, http.StatusBadRequest},
		{contracts.ErrInvalidName, TypeInvalidParameter, http.StatusBadRequest},
		{contracts.ErrInvalidValue, TypeInvalidParameter, http.StatusBadRequest},
		{contracts.ErrInvalidToken, TypeInvalidNextToken, http.StatusBadRequest},
		{errUnmapped, TypeInternalService, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.wantType+"/"+tt.err.Error(), func(t *testing.T) {
			// Wrapped, as the store returns them.
			got := ToError(t.Context(), fmt.Errorf("context: %w", tt.err))
			if got.Type != tt.wantType {
				t.Fatalf("type = %s, want %s", got.Type, tt.wantType)
			}
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %d, want %d", got.Status, tt.wantStatus)
			}
		})
	}
}

func TestToErrorPassesAPIErrorsThrough(t *testing.T) {
	want := ErrNotImplemented("RotateSecret is not implemented by this service.")

	got := ToError(t.Context(), fmt.Errorf("handler: %w", want))

	if got.Type != want.Type || got.Status != want.Status || got.Message != want.Message {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestErrorEnvelopeShape(t *testing.T) {
	// The SDKs read the error code from __type and the text from Message;
	// renaming either field makes every client report an unknown error.
	body, err := json.Marshal(ErrResourceNotFound("nope"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `{"__type":"ResourceNotFoundException","Message":"nope"}`; string(body) != want {
		t.Fatalf("envelope = %s, want %s", body, want)
	}
}

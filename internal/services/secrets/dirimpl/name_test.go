package dirimpl

import (
	"errors"
	"slices"
	"testing"

	"tule.dev/secret-store/internal/contracts"
)

func TestValidateName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "plain", input: "database"},
		{name: "path-like", input: "prod/app/database"},
		{name: "all punctuation", input: "a-b_c+d=e.f@g"},
		{name: "empty", input: "", wantErr: true},
		{name: "space", input: "my secret", wantErr: true},
		{name: "colon", input: "app:db", wantErr: true},
		{name: "too long", input: string(make([]byte, maxNameLen+1)), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateName(tt.input)
			if tt.wantErr && !errors.Is(err, contracts.ErrInvalidName) {
				t.Fatalf("validateName(%q) = %v, want ErrInvalidName", tt.input, err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateName(%q) = %v, want nil", tt.input, err)
			}
		})
	}
}

func TestCandidateNames(t *testing.T) {
	const arn = "arn:aws:secretsmanager:us-east-1:000000000000:secret:prod/db-AbC123"

	tests := []struct {
		name     string
		secretID string
		want     []string
	}{
		{name: "plain name", secretID: "prod/db", want: []string{"prod/db"}},
		{
			// A full ARN names the secret without the random suffix, but the
			// name may itself end that way, so both readings are candidates.
			name:     "full ARN",
			secretID: arn,
			want:     []string{"prod/db-AbC123", "prod/db"},
		},
		{
			name:     "partial ARN",
			secretID: "arn:aws:secretsmanager:us-east-1:000000000000:secret:prod/db",
			want:     []string{"prod/db"},
		},
		{
			name:     "ARN without a secret segment",
			secretID: "arn:aws:secretsmanager:us-east-1:000000000000:other:x",
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := candidateNames(tt.secretID); !slices.Equal(got, tt.want) {
				t.Fatalf("candidateNames(%q) = %v, want %v", tt.secretID, got, tt.want)
			}
		})
	}
}

func TestFileNameIsHashed(t *testing.T) {
	// Names contain "/", so the file must not inherit the name's shape.
	got := fileName("prod/app/db")
	if got == "" || got == secretsDir+"/prod/app/db.json" {
		t.Fatalf("fileName(%q) = %q, want a hashed path", "prod/app/db", got)
	}
	if got != fileName("prod/app/db") {
		t.Fatal("fileName is not stable for the same name")
	}
	if got == fileName("prod/app/other") {
		t.Fatal("fileName collides for different names")
	}
}

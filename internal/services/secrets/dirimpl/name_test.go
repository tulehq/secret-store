package dirimpl

import (
	"context"
	"errors"
	"strings"
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

func TestReadID(t *testing.T) {
	const base = "arn:aws:secretsmanager:us-east-1:000000000000:secret:"

	tests := []struct {
		name     string
		secretID string
		want     string
		how      idReading
		ok       bool
	}{
		{name: "plain name", secretID: "prod/db", want: "prod/db", how: byName, ok: true},
		{
			// An ARN ending in a hyphen and six characters is a full ARN
			// only, though a name may itself end that way.
			name: "full ARN", secretID: base + "prod/db-AbC123",
			want: "prod/db", how: byFullARN, ok: true,
		},
		{
			name: "partial ARN", secretID: base + "prod/db",
			want: "prod/db", how: byPartialARN, ok: true,
		},
		{name: "ARN without a secret name", secretID: base, ok: false},
		{
			name:     "ARN without a secret segment",
			secretID: "arn:aws:secretsmanager:us-east-1:000000000000:other:x", ok: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, how, ok := readID(tt.secretID)
			if got != tt.want || how != tt.how || ok != tt.ok {
				t.Fatalf("readID(%q) = %q, %v, %v; want %q, %v, %v",
					tt.secretID, got, how, ok, tt.want, tt.how, tt.ok)
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

func TestCreateSecretKeepsTheARNMintedForIt(t *testing.T) {
	svc := newTestService(t)

	arn, err := svc.NewSecretARN("app/db")
	if err != nil {
		t.Fatalf("new ARN: %v", err)
	}
	if !strings.HasPrefix(arn, "arn:aws:secretsmanager:us-east-1:000000000000:secret:app/db-") ||
		len(
			arn,
		) != len(
			"arn:aws:secretsmanager:us-east-1:000000000000:secret:app/db-",
		)+arnSuffixLen {
		t.Fatalf("ARN %s is not the name with a 6-character suffix", arn)
	}

	out, err := svc.CreateSecret(
		contracts.Unchecked(context.Background()),
		contracts.CreateSecretInput{
			ARN: arn, Name: "app/db", Payload: contracts.Payload{String: str("v")},
		},
	)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if out.ARN != arn {
		t.Fatalf("created %s, want the minted %s", out.ARN, arn)
	}

	other, err := svc.NewSecretARN("app/other")
	if err != nil {
		t.Fatalf("new ARN: %v", err)
	}
	_, err = svc.CreateSecret(
		contracts.Unchecked(context.Background()),
		contracts.CreateSecretInput{
			ARN: other, Name: "app/third", Payload: contracts.Payload{String: str("v")},
		},
	)
	if err == nil {
		t.Fatal("CreateSecret accepted an ARN minted for another name")
	}
}

func TestTagKeysStayUnique(t *testing.T) {
	svc := newTestService(t)
	dup := []contracts.Tag{{Key: "env", Value: "a"}, {Key: "env", Value: "b"}}

	_, err := svc.CreateSecret(
		contracts.Unchecked(context.Background()),
		contracts.CreateSecretInput{
			Name: "app/db", Payload: contracts.Payload{String: str("v")}, Tags: dup,
		},
	)
	if !errors.Is(err, contracts.ErrDuplicateTagKeys) {
		t.Fatalf("create with a repeated key: %v", err)
	}

	create(t, svc, "app/db", "v")
	if _, err = svc.TagSecret(
		contracts.Unchecked(context.Background()),
		"app/db",
		dup,
	); !errors.Is(
		err,
		contracts.ErrDuplicateTagKeys,
	) {
		t.Fatalf("tag with a repeated key: %v", err)
	}
	detail, err := svc.DescribeSecret(contracts.Unchecked(context.Background()), "app/db")
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Tags) != 0 {
		t.Fatalf("the refused tags were stored: %v", detail.Tags)
	}
}

func TestASuffixShapedARNIsReadAsAFullARNOnly(t *testing.T) {
	svc := newTestService(t)
	const base = "arn:aws:secretsmanager:us-east-1:000000000000:secret:"
	victim := base + "app/db-CTFz8F"
	bg := contracts.Unchecked(context.Background())

	_, err := svc.CreateSecret(bg, contracts.CreateSecretInput{
		ARN: victim, Name: "app/db", Payload: contracts.Payload{String: str("victim")},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A decoy whose name is the victim's ARN segment: read as a partial ARN,
	// the victim's ARN would name it.
	decoy := create(t, svc, "app/db-CTFz8F", "decoy")

	requireEqual(t, currentValue(t, svc, victim), "victim", "the victim's full ARN")
	requireEqual(t, currentValue(t, svc, "app/db-CTFz8F"), "decoy", "the decoy's name")
	requireEqual(t, currentValue(t, svc, decoy.ARN), "decoy", "the decoy's full ARN")

	// With the victim gone, its ARN names nothing: it is never read as a
	// partial ARN of the decoy, as the troubleshooting note says a partial
	// ARN of MySecret-abcdef may not be found.
	if _, err = svc.DeleteSecret(bg, contracts.DeleteSecretInput{
		SecretID: victim, Force: true,
	}); err != nil {
		t.Fatal(err)
	}
	_, err = svc.GetSecretValue(bg, contracts.GetSecretValueInput{SecretID: victim})
	if !errors.Is(err, contracts.ErrSecretNotFound) {
		t.Fatalf("the victim's ARN after deletion: %v", err)
	}

	// A partial ARN that is not suffix-shaped still finds its secret.
	create(t, svc, "app/plain", "plain")
	requireEqual(t, currentValue(t, svc, base+"app/plain"), "plain", "a partial ARN")
}

func requireEqual[T comparable](t *testing.T, got, want T, what string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

func TestAnOperationWithoutACheckFailsRatherThanActs(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "app/db", "v")

	_, err := svc.GetSecretValue(
		context.Background(),
		contracts.GetSecretValueInput{SecretID: "app/db"},
	)
	if !errors.Is(err, contracts.ErrNoCheck) {
		t.Fatalf("read without a check: %v", err)
	}
	_, err = svc.DeleteSecret(context.Background(), contracts.DeleteSecretInput{
		SecretID: "app/db", Force: true,
	})
	if !errors.Is(err, contracts.ErrNoCheck) {
		t.Fatalf("delete without a check: %v", err)
	}
	requireEqual(t, currentValue(t, svc, "app/db"), "v", "the secret after both")
}

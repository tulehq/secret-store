package dirimpl

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/contracts"
)

// newTestService returns a Service on a fresh directory, with a clock the test
// controls so dates are predictable.
func newTestService(t *testing.T) *Service {
	t.Helper()

	svc := NewService(&Settings{
		RootDir:   t.TempDir(),
		Region:    "us-east-1",
		AccountID: "000000000000",
	})(&gas.NopLogger{})

	clock := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	svc.now = func() time.Time { return clock }

	if err := svc.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() {
		if err := svc.Close(context.Background()); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return svc
}

func str(s string) *string { return &s }

// create stores a secret holding value and returns it.
func create(t *testing.T, svc *Service, name, value string) *contracts.SecretVersion {
	t.Helper()

	out, err := svc.CreateSecret(context.Background(), contracts.CreateSecretInput{
		Name:    name,
		Payload: contracts.Payload{String: str(value)},
	})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return out
}

// currentValue returns the AWSCURRENT string value of a secret.
func currentValue(t *testing.T, svc *Service, secretID string) string {
	t.Helper()

	out, err := svc.GetSecretValue(context.Background(), contracts.GetSecretValueInput{
		SecretID: secretID,
	})
	if err != nil {
		t.Fatalf("get %s: %v", secretID, err)
	}
	if out.Payload.String == nil {
		t.Fatalf("get %s: no string value", secretID)
	}
	return *out.Payload.String
}

func TestCreateAndGet(t *testing.T) {
	svc := newTestService(t)
	created := create(t, svc, "prod/db", `{"password":"placeholder"}`)

	if created.VersionID == "" {
		t.Fatal("create returned no version ID")
	}
	if !slices.Equal(created.VersionStages, []string{contracts.StageCurrent}) {
		t.Fatalf("stages = %v, want [AWSCURRENT]", created.VersionStages)
	}
	if got := currentValue(t, svc, "prod/db"); got != `{"password":"placeholder"}` {
		t.Fatalf("value = %q", got)
	}
	// Both identifiers reach the same secret.
	if got := currentValue(t, svc, created.ARN); got != `{"password":"placeholder"}` {
		t.Fatalf("value by ARN = %q", got)
	}
}

func TestCreateRejects(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "taken", "v1")

	tests := []struct {
		want error
		name string
		in   contracts.CreateSecretInput
	}{
		{
			name: "duplicate name",
			in: contracts.CreateSecretInput{
				Name:    "taken",
				Payload: contracts.Payload{String: str("v2")},
			},
			want: contracts.ErrSecretExists,
		},
		{
			name: "invalid name",
			in: contracts.CreateSecretInput{
				Name:    "not valid",
				Payload: contracts.Payload{String: str("v1")},
			},
			want: contracts.ErrInvalidName,
		},
		{
			name: "string and binary",
			in: contracts.CreateSecretInput{
				Name:    "both",
				Payload: contracts.Payload{String: str("v1"), Binary: []byte("v1")},
			},
			want: contracts.ErrInvalidValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreateSecret(context.Background(), tt.in)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestGetMissing(t *testing.T) {
	svc := newTestService(t)

	_, err := svc.GetSecretValue(context.Background(), contracts.GetSecretValueInput{
		SecretID: "absent",
	})
	if !errors.Is(err, contracts.ErrSecretNotFound) {
		t.Fatalf("err = %v, want ErrSecretNotFound", err)
	}
}

func TestPutMovesStagingLabels(t *testing.T) {
	svc := newTestService(t)
	first := create(t, svc, "rotating", "v1")

	second, err := svc.PutSecretValue(context.Background(), contracts.PutSecretValueInput{
		SecretID: "rotating",
		Payload:  contracts.Payload{String: str("v2")},
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	if got := currentValue(t, svc, "rotating"); got != "v2" {
		t.Fatalf("AWSCURRENT = %q, want v2", got)
	}

	prev, err := svc.GetSecretValue(context.Background(), contracts.GetSecretValueInput{
		SecretID:     "rotating",
		VersionStage: contracts.StagePrevious,
	})
	if err != nil {
		t.Fatalf("get AWSPREVIOUS: %v", err)
	}
	if prev.VersionID != first.VersionID {
		t.Fatalf("AWSPREVIOUS = %s, want the first version %s", prev.VersionID, first.VersionID)
	}

	// The old value stays reachable by version ID.
	byID, err := svc.GetSecretValue(context.Background(), contracts.GetSecretValueInput{
		SecretID:  "rotating",
		VersionID: first.VersionID,
	})
	if err != nil {
		t.Fatalf("get by version ID: %v", err)
	}
	if *byID.Payload.String != "v1" {
		t.Fatalf("first version = %q, want v1", *byID.Payload.String)
	}
	if second.VersionID == first.VersionID {
		t.Fatal("put reused the version ID")
	}
}

func TestPutWithVersionIDIsIdempotent(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "token", "v1")

	in := contracts.PutSecretValueInput{
		SecretID:  "token",
		VersionID: "11111111-1111-4111-8111-111111111111",
		Payload:   contracts.Payload{String: str("v2")},
	}
	first, err := svc.PutSecretValue(context.Background(), in)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	again, err := svc.PutSecretValue(context.Background(), in)
	if err != nil {
		t.Fatalf("put again: %v", err)
	}
	if again.VersionID != first.VersionID {
		t.Fatalf("retry made version %s, want %s", again.VersionID, first.VersionID)
	}

	in.Payload = contracts.Payload{String: str("different")}
	if _, err = svc.PutSecretValue(context.Background(), in); !errors.Is(
		err, contracts.ErrVersionExists,
	) {
		t.Fatalf("err = %v, want ErrVersionExists", err)
	}
}

func TestBinaryValueRoundTrips(t *testing.T) {
	svc := newTestService(t)

	if _, err := svc.CreateSecret(context.Background(), contracts.CreateSecretInput{
		Name:    "binary",
		Payload: contracts.Payload{Binary: []byte{0x00, 0x01, 0xff}},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	out, err := svc.GetSecretValue(context.Background(), contracts.GetSecretValueInput{
		SecretID: "binary",
	})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if out.Payload.String != nil {
		t.Fatal("a binary secret reported a string value")
	}
	if !slices.Equal(out.Payload.Binary, []byte{0x00, 0x01, 0xff}) {
		t.Fatalf("binary = %v", out.Payload.Binary)
	}
}

func TestDeleteAndRestore(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "doomed", "v1")

	out, err := svc.DeleteSecret(context.Background(), contracts.DeleteSecretInput{
		SecretID: "doomed",
	})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if want := svc.now().UTC().Add(contracts.DefaultRecoveryWindow); !out.DeletionDate.Equal(want) {
		t.Fatalf("deletion date = %v, want %v", out.DeletionDate, want)
	}

	_, err = svc.GetSecretValue(context.Background(), contracts.GetSecretValueInput{
		SecretID: "doomed",
	})
	if !errors.Is(err, contracts.ErrSecretDeleted) {
		t.Fatalf("get after delete: %v, want ErrSecretDeleted", err)
	}

	// Describe still answers, which is what makes the scheduled state visible.
	if _, err = svc.DescribeSecret(context.Background(), "doomed"); err != nil {
		t.Fatalf("describe after delete: %v", err)
	}

	if _, err = svc.RestoreSecret(context.Background(), "doomed"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := currentValue(t, svc, "doomed"); got != "v1" {
		t.Fatalf("value after restore = %q", got)
	}
	if _, err = svc.RestoreSecret(context.Background(), "doomed"); !errors.Is(
		err, contracts.ErrSecretNotDeleted,
	) {
		t.Fatalf("restore again: %v, want ErrSecretNotDeleted", err)
	}
}

func TestForceDeleteRemovesTheSecret(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "gone", "v1")

	if _, err := svc.DeleteSecret(context.Background(), contracts.DeleteSecretInput{
		SecretID: "gone",
		Force:    true,
	}); err != nil {
		t.Fatalf("force delete: %v", err)
	}

	if _, err := svc.DescribeSecret(context.Background(), "gone"); !errors.Is(
		err, contracts.ErrSecretNotFound,
	) {
		t.Fatalf("describe after force delete: %v, want ErrSecretNotFound", err)
	}
	// The name is free again.
	create(t, svc, "gone", "v2")
}

func TestTags(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "tagged", "v1")

	if _, err := svc.TagSecret(context.Background(), "tagged", []contracts.Tag{
		{Key: "env", Value: "dev"}, {Key: "team", Value: "platform"},
	}); err != nil {
		t.Fatalf("tag: %v", err)
	}
	// Tagging an existing key replaces its value rather than duplicating it.
	if _, err := svc.TagSecret(context.Background(), "tagged", []contracts.Tag{
		{Key: "env", Value: "test"},
	}); err != nil {
		t.Fatalf("retag: %v", err)
	}
	if _, err := svc.UntagSecret(
		context.Background(),
		"tagged",
		[]string{"team", "absent"},
	); err != nil {
		t.Fatalf("untag: %v", err)
	}

	detail, err := svc.DescribeSecret(context.Background(), "tagged")
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if !slices.Equal(detail.Tags, []contracts.Tag{{Key: "env", Value: "test"}}) {
		t.Fatalf("tags = %v", detail.Tags)
	}
}

func TestUpdateSecretVersionStage(t *testing.T) {
	svc := newTestService(t)
	first := create(t, svc, "staged", "v1")

	second, err := svc.PutSecretValue(context.Background(), contracts.PutSecretValueInput{
		SecretID:      "staged",
		Payload:       contracts.Payload{String: str("v2")},
		VersionStages: []string{contracts.StagePending},
	})
	if err != nil {
		t.Fatalf("put pending: %v", err)
	}
	// A pending version does not disturb AWSCURRENT.
	if got := currentValue(t, svc, "staged"); got != "v1" {
		t.Fatalf("AWSCURRENT = %q, want v1", got)
	}

	if _, err = svc.UpdateSecretVersionStage(
		context.Background(),
		contracts.UpdateSecretVersionStageInput{
			SecretID:     "staged",
			VersionStage: contracts.StageCurrent,
			MoveTo:       second.VersionID,
			RemoveFrom:   first.VersionID,
		},
	); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if got := currentValue(t, svc, "staged"); got != "v2" {
		t.Fatalf("AWSCURRENT after promotion = %q, want v2", got)
	}

	// Moving a label off a version that does not hold it is an error.
	_, err = svc.UpdateSecretVersionStage(
		context.Background(),
		contracts.UpdateSecretVersionStageInput{
			SecretID:     "staged",
			VersionStage: contracts.StagePending,
			RemoveFrom:   first.VersionID,
		},
	)
	if !errors.Is(err, contracts.ErrStageMismatch) {
		t.Fatalf("err = %v, want ErrStageMismatch", err)
	}
}

func TestListSecretsPages(t *testing.T) {
	svc := newTestService(t)
	for _, name := range []string{"c", "a", "b"} {
		create(t, svc, name, "v")
	}

	first, err := svc.ListSecrets(context.Background(), contracts.ListSecretsInput{MaxResults: 2})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := names(first.Secrets); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("first page = %v, want [a b]", got)
	}
	if first.NextToken == "" {
		t.Fatal("first page has no next token")
	}

	second, err := svc.ListSecrets(context.Background(), contracts.ListSecretsInput{
		MaxResults: 2,
		NextToken:  first.NextToken,
	})
	if err != nil {
		t.Fatalf("list page two: %v", err)
	}
	if got := names(second.Secrets); !slices.Equal(got, []string{"c"}) {
		t.Fatalf("second page = %v, want [c]", got)
	}
	if second.NextToken != "" {
		t.Fatalf("last page has next token %q", second.NextToken)
	}

	if _, err = svc.ListSecrets(context.Background(), contracts.ListSecretsInput{
		NextToken: "not base64!",
	}); !errors.Is(err, contracts.ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestListSecretsHidesScheduledDeletions(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "kept", "v")
	create(t, svc, "scheduled", "v")

	if _, err := svc.DeleteSecret(context.Background(), contracts.DeleteSecretInput{
		SecretID: "scheduled",
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	out, err := svc.ListSecrets(context.Background(), contracts.ListSecretsInput{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if got := names(out.Secrets); !slices.Equal(got, []string{"kept"}) {
		t.Fatalf("list = %v, want [kept]", got)
	}

	out, err = svc.ListSecrets(context.Background(), contracts.ListSecretsInput{
		IncludeDeleted: true,
	})
	if err != nil {
		t.Fatalf("list including deletions: %v", err)
	}
	if got := names(out.Secrets); !slices.Equal(got, []string{"kept", "scheduled"}) {
		t.Fatalf("list = %v, want [kept scheduled]", got)
	}
}

func TestListSecretVersions(t *testing.T) {
	svc := newTestService(t)
	first := create(t, svc, "versioned", "v1")
	second, err := svc.PutSecretValue(context.Background(), contracts.PutSecretValueInput{
		SecretID: "versioned",
		Payload:  contracts.Payload{String: str("v2")},
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	out, err := svc.ListSecretVersions(context.Background(), contracts.ListSecretVersionsInput{
		SecretID: "versioned",
	})
	if err != nil {
		t.Fatalf("list versions: %v", err)
	}
	if len(out.Versions) != 2 {
		t.Fatalf("versions = %v, want two", out.Versions)
	}
	// Newest first.
	if out.Versions[0].VersionID != second.VersionID ||
		out.Versions[1].VersionID != first.VersionID {
		t.Fatalf("versions out of order: %v", out.Versions)
	}
}

func TestSecretsSurviveAReopen(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "persisted", "v1")

	// A second service on the same directory is what a restart looks like.
	reopened := NewService(svc.settings)(&gas.NopLogger{})
	if err := reopened.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	defer func() {
		if err := reopened.Close(context.Background()); err != nil {
			t.Errorf("close: %v", err)
		}
	}()

	if got := currentValue(t, reopened, "persisted"); got != "v1" {
		t.Fatalf("value after reopen = %q, want v1", got)
	}
}

func names(details []contracts.SecretDetail) []string {
	out := make([]string, 0, len(details))
	for _, d := range details {
		out = append(out, d.Name)
	}
	return out
}

func TestUpdateWithVersionIDIsIdempotent(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "updated", "v1")

	// The SDK fills ClientRequestToken in for UpdateSecret, so a retried
	// call arrives with the version ID of the one before it.
	in := contracts.UpdateSecretInput{
		SecretID:  "updated",
		VersionID: "33333333-3333-4333-8333-333333333333",
		Payload:   contracts.Payload{String: str("v2")},
	}
	first, err := svc.UpdateSecret(context.Background(), in)
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	again, err := svc.UpdateSecret(context.Background(), in)
	if err != nil {
		t.Fatalf("update again: %v", err)
	}
	if again.VersionID != first.VersionID {
		t.Fatalf("retry made version %s, want %s", again.VersionID, first.VersionID)
	}

	versions, err := svc.ListSecretVersions(context.Background(),
		contracts.ListSecretVersionsInput{SecretID: "updated", IncludeDeprecated: true})
	if err != nil {
		t.Fatalf("list versions: %v", err)
	}
	if len(versions.Versions) != 2 {
		t.Fatalf(
			"versions = %d, want 2: a retry must not store a duplicate",
			len(versions.Versions),
		)
	}

	in.Payload = contracts.Payload{String: str("different")}
	if _, err = svc.UpdateSecret(context.Background(), in); !errors.Is(
		err, contracts.ErrVersionExists,
	) {
		t.Fatalf("err = %v, want ErrVersionExists", err)
	}
}

func TestUpdateAppliesTheDescriptionOnARetriedToken(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "retried", "v1")

	in := contracts.UpdateSecretInput{
		SecretID:  "retried",
		VersionID: "44444444-4444-4444-8444-444444444444",
		Payload:   contracts.Payload{String: str("v2")},
	}
	if _, err := svc.UpdateSecret(context.Background(), in); err != nil {
		t.Fatalf("update: %v", err)
	}

	// The reused version ID must not swallow the rest of the call.
	in.Description = str("described on the retry")
	if _, err := svc.UpdateSecret(context.Background(), in); err != nil {
		t.Fatalf("update again: %v", err)
	}

	detail, err := svc.DescribeSecret(context.Background(), "retried")
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if detail.Description != "described on the retry" {
		t.Fatalf("description = %q, want the one sent with the retry", detail.Description)
	}
}

// stagedSecret returns a secret with two versions, AWSCURRENT on the first and
// AWSPENDING on the second.
func stagedSecret(t *testing.T, svc *Service) (first, second *contracts.SecretVersion) {
	t.Helper()

	first = create(t, svc, "staging", "v1")
	second, err := svc.PutSecretValue(context.Background(), contracts.PutSecretValueInput{
		SecretID:      "staging",
		Payload:       contracts.Payload{String: str("v2")},
		VersionStages: []string{contracts.StagePending},
	})
	if err != nil {
		t.Fatalf("put pending: %v", err)
	}
	return first, second
}

func TestMovingCurrentCarriesPreviousAlong(t *testing.T) {
	svc := newTestService(t)
	first, second := stagedSecret(t, svc)

	// "Whenever you move AWSCURRENT, Secrets Manager automatically moves the
	// label AWSPREVIOUS to the version that AWSCURRENT was removed from."
	// -- UpdateSecretVersionStage, aws-sdk-go-v2 secretsmanager v1.50.5.
	if _, err := svc.UpdateSecretVersionStage(
		context.Background(),
		contracts.UpdateSecretVersionStageInput{
			SecretID:     "staging",
			VersionStage: contracts.StageCurrent,
			MoveTo:       second.VersionID,
			RemoveFrom:   first.VersionID,
		},
	); err != nil {
		t.Fatalf("promote: %v", err)
	}

	previous, err := svc.GetSecretValue(context.Background(), contracts.GetSecretValueInput{
		SecretID:     "staging",
		VersionStage: contracts.StagePrevious,
	})
	if err != nil {
		t.Fatalf("get AWSPREVIOUS: %v", err)
	}
	if previous.VersionID != first.VersionID {
		t.Fatalf("AWSPREVIOUS = %s, want the version AWSCURRENT left, %s",
			previous.VersionID, first.VersionID)
	}
}

func TestStageMoveRequiresTheVersionItIsAttachedTo(t *testing.T) {
	svc := newTestService(t)
	_, second := stagedSecret(t, svc)

	// "If the staging label you are trying to attach to one version is
	// already attached to a different version, then you must include this
	// parameter [...] If the label is attached and you either do not specify
	// this parameter, or the version ID does not match, then the operation
	// fails." -- RemoveFromVersionId, same package.
	_, err := svc.UpdateSecretVersionStage(
		context.Background(),
		contracts.UpdateSecretVersionStageInput{
			SecretID:     "staging",
			VersionStage: contracts.StageCurrent,
			MoveTo:       second.VersionID,
		},
	)
	if !errors.Is(err, contracts.ErrStageAttached) {
		t.Fatalf("err = %v, want ErrStageAttached", err)
	}
}

func TestCurrentStageCannotBeRemovedOutright(t *testing.T) {
	svc := newTestService(t)
	first, _ := stagedSecret(t, svc)

	_, err := svc.UpdateSecretVersionStage(
		context.Background(),
		contracts.UpdateSecretVersionStageInput{
			SecretID:     "staging",
			VersionStage: contracts.StageCurrent,
			RemoveFrom:   first.VersionID,
		},
	)
	if !errors.Is(err, contracts.ErrCurrentStageRequired) {
		t.Fatalf("err = %v, want ErrCurrentStageRequired", err)
	}

	// The secret still reads, which is the point of refusing.
	if got := currentValue(t, svc, "staging"); got != "v1" {
		t.Fatalf("AWSCURRENT = %q, want it left in place", got)
	}
}

func TestForceDeleteNeverFails(t *testing.T) {
	// "If you forcibly delete an already deleted or nonexistent secret, the
	// operation does not fail." -- DeleteSecret, aws-sdk-go-v2
	// secretsmanager v1.50.5.
	svc := newTestService(t)
	create(t, svc, "scheduled", "v1")
	if _, err := svc.DeleteSecret(context.Background(), contracts.DeleteSecretInput{
		SecretID: "scheduled",
	}); err != nil {
		t.Fatalf("schedule deletion: %v", err)
	}

	tests := []struct {
		name     string
		secretID string
	}{
		{name: "already scheduled for deletion", secretID: "scheduled"},
		{name: "never existed", secretID: "absent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := svc.DeleteSecret(context.Background(), contracts.DeleteSecretInput{
				SecretID: tt.secretID,
				Force:    true,
			})
			if err != nil {
				t.Fatalf("force delete: %v", err)
			}
			if out.Name != tt.secretID {
				t.Fatalf("name = %q, want %q", out.Name, tt.secretID)
			}
		})
	}

	// The scheduled secret really is gone, not just reported as deleted.
	if _, err := svc.DescribeSecret(context.Background(), "scheduled"); !errors.Is(
		err, contracts.ErrSecretNotFound,
	) {
		t.Fatalf("describe after force delete: %v, want ErrSecretNotFound", err)
	}
}

func TestValueSizeLimit(t *testing.T) {
	svc := newTestService(t)
	atLimit := strings.Repeat("a", contracts.MaxValueSize)

	if _, err := svc.CreateSecret(context.Background(), contracts.CreateSecretInput{
		Name:    "at-limit",
		Payload: contracts.Payload{String: &atLimit},
	}); err != nil {
		t.Fatalf("create at the limit: %v", err)
	}

	// One byte over is rejected here, so a value that works against this
	// service works against the real one too.
	over := atLimit + "a"
	_, err := svc.CreateSecret(context.Background(), contracts.CreateSecretInput{
		Name:    "over-limit",
		Payload: contracts.Payload{String: &over},
	})
	if !errors.Is(err, contracts.ErrValueTooLarge) {
		t.Fatalf("create over the limit: %v, want ErrValueTooLarge", err)
	}

	_, err = svc.PutSecretValue(context.Background(), contracts.PutSecretValueInput{
		SecretID: "at-limit",
		Payload:  contracts.Payload{Binary: []byte(over)},
	})
	if !errors.Is(err, contracts.ErrValueTooLarge) {
		t.Fatalf("put over the limit: %v, want ErrValueTooLarge", err)
	}
}

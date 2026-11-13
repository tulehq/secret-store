package dirimpl

import (
	"context"
	"errors"
	"testing"

	"tule.dev/secret-store/internal/contracts"
)

const testPolicy = `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
	`"Principal":{"AWS":"111122223333"},"Action":"secretsmanager:GetSecretValue","Resource":"*"}}`

func storedPolicy(t *testing.T, svc *Service) string {
	t.Helper()
	out, err := svc.GetResourcePolicy(contracts.Unchecked(context.Background()), "app/db")
	if err != nil {
		t.Fatalf("get the resource policy: %v", err)
	}
	return out.Policy
}

func TestResourcePolicyRoundTrips(t *testing.T) {
	svc := newTestService(t)
	ctx := contracts.Unchecked(context.Background())
	create(t, svc, "app/db", "v")

	if got := storedPolicy(t, svc); got != "" {
		t.Fatalf("a new secret has the policy %q", got)
	}
	ref, err := svc.PutResourcePolicy(ctx, "app/db", testPolicy)
	if err != nil || ref.Name != "app/db" {
		t.Fatalf("put: %+v, %v", ref, err)
	}
	if got := storedPolicy(t, svc); got != testPolicy {
		t.Fatalf("got %q", got)
	}
	detail, err := svc.DescribeSecret(ctx, "app/db")
	if err != nil || detail.ResourcePolicy != testPolicy {
		t.Fatalf("the described secret does not carry its policy: %+v, %v", detail, err)
	}

	if _, err = svc.DeleteResourcePolicy(ctx, "app/db"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := storedPolicy(t, svc); got != "" {
		t.Fatalf("after delete: %q", got)
	}
	// Deleting a policy the secret no longer has is not an error.
	if _, err = svc.DeleteResourcePolicy(ctx, "app/db"); err != nil {
		t.Fatalf("delete again: %v", err)
	}
}

// scheduledWithPolicy returns a store holding app/db, with testPolicy,
// scheduled for deletion.
func scheduledWithPolicy(t *testing.T) (*Service, context.Context) {
	t.Helper()
	svc := newTestService(t)
	ctx := contracts.Unchecked(context.Background())
	create(t, svc, "app/db", "v")
	if _, err := svc.PutResourcePolicy(ctx, "app/db", testPolicy); err != nil {
		t.Fatal(err)
	}
	_, err := svc.DeleteSecret(ctx, contracts.DeleteSecretInput{SecretID: "app/db"})
	if err != nil {
		t.Fatal(err)
	}
	return svc, ctx
}

func TestAScheduledSecretKeepsItsPolicyAndRefusesThePolicyOperations(t *testing.T) {
	svc, ctx := scheduledWithPolicy(t)

	// Its checks still see the policy.
	detail, err := svc.DescribeSecret(ctx, "app/db")
	if err != nil || detail.ResourcePolicy != testPolicy {
		t.Fatalf("scheduled secret: %+v, %v", detail, err)
	}
	if _, err = svc.GetResourcePolicy(ctx, "app/db"); !errors.Is(err, contracts.ErrSecretDeleted) {
		t.Fatalf("get: want ErrSecretDeleted, got %v", err)
	}
	_, err = svc.PutResourcePolicy(ctx, "app/db", testPolicy)
	if !errors.Is(err, contracts.ErrSecretDeleted) {
		t.Fatalf("put: want ErrSecretDeleted, got %v", err)
	}
	if _, err = svc.DeleteResourcePolicy(
		ctx,
		"app/db",
	); !errors.Is(
		err,
		contracts.ErrSecretDeleted,
	) {
		t.Fatalf("delete: want ErrSecretDeleted, got %v", err)
	}
}

func TestARestoredSecretHasItsPolicyAndAPurgedOneLosesIt(t *testing.T) {
	svc, ctx := scheduledWithPolicy(t)
	if _, err := svc.RestoreSecret(ctx, "app/db"); err != nil {
		t.Fatal(err)
	}
	if got := storedPolicy(t, svc); got != testPolicy {
		t.Fatalf("after restore: %q", got)
	}

	// Purged and created again, the secret has no policy.
	if _, err := svc.DeleteSecret(ctx, contracts.DeleteSecretInput{
		SecretID: "app/db", Force: true,
	}); err != nil {
		t.Fatal(err)
	}
	create(t, svc, "app/db", "v")
	if got := storedPolicy(t, svc); got != "" {
		t.Fatalf("the recreated secret has the policy %q", got)
	}
}

func TestPolicyOperationsRunTheCheck(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "app/db", "v")
	refuse := errors.New("refused")
	ctx := contracts.WithCheck(context.Background(), func(*contracts.SecretDetail) error {
		return refuse
	})
	if _, err := svc.PutResourcePolicy(ctx, "app/db", testPolicy); !errors.Is(err, refuse) {
		t.Fatalf("put: %v", err)
	}
	if _, err := svc.GetResourcePolicy(ctx, "app/db"); !errors.Is(err, refuse) {
		t.Fatalf("get: %v", err)
	}
	if _, err := svc.DeleteResourcePolicy(ctx, "app/db"); !errors.Is(err, refuse) {
		t.Fatalf("delete: %v", err)
	}
	if got := storedPolicy(t, svc); got != "" {
		t.Fatalf("a refused put stored %q", got)
	}
}

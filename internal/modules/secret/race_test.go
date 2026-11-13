package secret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gasmod/gas"
	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/authz"
	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/services/secrets/dirimpl"
	"tule.dev/secret-store/internal/smapi"
)

// swapper is the real store, with a mutation run when an operation reaches
// it: after the handler has built its check, before the store acts. It is
// the window a caller controls by racing its own writes against a read.
type swapper struct {
	*dirimpl.Service
	mutate func()
}

func (s *swapper) GetSecretValue(
	ctx context.Context,
	in contracts.GetSecretValueInput,
) (*contracts.SecretValue, error) {
	if s.mutate != nil {
		s.mutate()
	}
	return s.Service.GetSecretValue(ctx, in)
}

const denyProd = `{"Version":"2012-10-17","Statement":[` +
	`{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"},` +
	`{"Effect":"Deny","Action":"secretsmanager:GetSecretValue","Resource":"*",` +
	`"Condition":{"StringEquals":{"aws:ResourceTag/env":"prod"}}}]}`

func newSwapper(t *testing.T) (*swapper, *Module, context.Context) {
	t.Helper()
	svc := dirimpl.NewService(&dirimpl.Settings{
		RootDir: t.TempDir(), Region: "us-east-1", AccountID: "000000000000",
	})(&gas.NopLogger{})
	if err := svc.Init(contracts.Unchecked(context.Background())); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(contracts.Unchecked(context.Background())) })

	store := &swapper{Service: svc}
	az := authz.New("us-east-1", "000000000000")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r = r.WithContext(sigv4.NewContext(r.Context(), sigv4.Principal{
		AccountID: "000000000000", ARN: devARN,
		Policies: []json.RawMessage{json.RawMessage(denyProd)},
	}))
	r, err := az.Attach(r)
	if err != nil {
		t.Fatal(err)
	}
	return store, &Module{secrets: store, authz: az}, r.Context()
}

func put(t *testing.T, svc contracts.SecretsProvider, in contracts.CreateSecretInput) {
	t.Helper()
	v := "value of " + in.Name
	in.Payload = contracts.Payload{String: &v}
	if _, err := svc.CreateSecret(contracts.Unchecked(context.Background()), in); err != nil {
		t.Fatalf("create %s: %v", in.Name, err)
	}
}

func forceDelete(t *testing.T, svc contracts.SecretsProvider, id string) {
	t.Helper()
	if _, err := svc.DeleteSecret(
		contracts.Unchecked(context.Background()),
		contracts.DeleteSecretInput{
			SecretID: id, Force: true,
		},
	); err != nil {
		t.Fatalf("delete %s: %v", id, err)
	}
}

// read runs GetSecretValue as the handler does: the check built first, the
// store called with it.
func read(ctx context.Context, m *Module, id string) (*contracts.SecretValue, error) {
	sctx := m.guardSecret(ctx, "GetSecretValue", id, nil)
	return m.secrets.GetSecretValue(sctx, contracts.GetSecretValueInput{SecretID: id})
}

func TestASecretSwappedBeforeTheStoreActsIsTheOneChecked(t *testing.T) {
	store, m, ctx := newSwapper(t)
	put(t, store.Service, contracts.CreateSecretInput{Name: "app/db"})

	// Between the check being built and the store acting, app/db is replaced
	// by a secret tagged env=prod. The check must see the replacement.
	store.mutate = func() {
		forceDelete(t, store.Service, "app/db")
		put(t, store.Service, contracts.CreateSecretInput{
			Name: "app/db", Tags: []contracts.Tag{{Key: "env", Value: "prod"}},
		})
	}
	out, err := read(ctx, m, "app/db")
	if err == nil {
		t.Fatalf("read %s, tagged env=prod, past a Deny on that tag", *out.Payload.String)
	}
	requireAccessDenied(t, err)
}

func TestADecoyDeletedBeforeTheStoreActsDoesNotUnlockTheVictim(t *testing.T) {
	// The reviewer's case: the victim, tagged env=prod, and an untagged
	// decoy named after the victim's ARN segment; the read names the
	// victim's full ARN while the decoy is force-deleted.
	store, m, ctx := newSwapper(t)
	victim := "arn:aws:secretsmanager:us-east-1:000000000000:secret:app/db-CTFz8F"
	put(t, store.Service, contracts.CreateSecretInput{
		ARN: victim, Name: "app/db", Tags: []contracts.Tag{{Key: "env", Value: "prod"}},
	})
	put(t, store.Service, contracts.CreateSecretInput{Name: "app/db-CTFz8F"})

	store.mutate = func() { forceDelete(t, store.Service, "app/db-CTFz8F") }
	if out, err := read(ctx, m, victim); err == nil {
		t.Fatalf("read %s past the Deny", *out.Payload.String)
	} else {
		requireAccessDenied(t, err)
	}

	// Without the swap, too: the victim's full ARN names the victim.
	put(t, store.Service, contracts.CreateSecretInput{Name: "app/db-CTFz8F"})
	store.mutate = nil
	_, err := read(ctx, m, victim)
	requireAccessDenied(t, err)
}

func TestARefusedCheckLeavesTheSecretUntouched(t *testing.T) {
	// Every store operation on one secret runs the check before acting, and
	// a refusal stops it.
	store, _, _ := newSwapper(t)
	svc := store.Service
	put(t, svc, contracts.CreateSecretInput{Name: "app/db"})
	refused := contracts.WithCheck(context.Background(), func(found *contracts.SecretDetail) error {
		if found == nil || found.Name != "app/db" {
			t.Errorf("the check saw %+v, want app/db", found)
		}
		return smapi.ErrAccessDenied("refused")
	})
	ops := refusableOps(refused, svc)
	for name, op := range ops {
		var apiErr *smapi.Error
		if err := op(); !errors.As(err, &apiErr) || apiErr.Type != smapi.TypeAccessDenied {
			t.Errorf("%s: want the check's refusal, got %v", name, err)
		}
	}

	requireUnchanged(t, svc)

	// A missing secret is checked too, on nil.
	missing := contracts.WithCheck(context.Background(), func(found *contracts.SecretDetail) error {
		if found != nil {
			t.Errorf("the check saw %+v for a missing secret", found)
		}
		return smapi.ErrAccessDenied("refused")
	})
	_, err := svc.GetSecretValue(missing, contracts.GetSecretValueInput{SecretID: "app/none"})
	requireAccessDenied(t, err)
}

// refusableOps calls every store operation on the secret app/db with ctx.
func refusableOps(ctx context.Context, svc *dirimpl.Service) map[string]func() error {
	v := "changed"
	return map[string]func() error{
		"GetSecretValue": func() error {
			_, err := svc.GetSecretValue(ctx, contracts.GetSecretValueInput{SecretID: "app/db"})
			return err
		},
		"PutSecretValue": func() error {
			_, err := svc.PutSecretValue(ctx, contracts.PutSecretValueInput{
				SecretID: "app/db", Payload: contracts.Payload{String: &v},
			})
			return err
		},
		"UpdateSecret": func() error {
			_, err := svc.UpdateSecret(ctx, contracts.UpdateSecretInput{
				SecretID: "app/db", Description: &v,
			})
			return err
		},
		"DescribeSecret": func() error {
			_, err := svc.DescribeSecret(ctx, "app/db")
			return err
		},
		"DeleteSecret": func() error {
			_, err := svc.DeleteSecret(ctx, contracts.DeleteSecretInput{SecretID: "app/db"})
			return err
		},
		"ForceDeleteSecret": func() error {
			_, err := svc.DeleteSecret(ctx, contracts.DeleteSecretInput{
				SecretID: "app/db", Force: true,
			})
			return err
		},
		"RestoreSecret": func() error {
			_, err := svc.RestoreSecret(ctx, "app/db")
			return err
		},
		"ListSecretVersions": func() error {
			_, err := svc.ListSecretVersions(ctx,
				contracts.ListSecretVersionsInput{SecretID: "app/db"})
			return err
		},
		"UpdateSecretVersionStage": func() error {
			_, err := svc.UpdateSecretVersionStage(ctx, contracts.UpdateSecretVersionStageInput{
				SecretID: "app/db", VersionStage: "X", MoveTo: "nope",
			})
			return err
		},
		"TagSecret": func() error {
			_, err := svc.TagSecret(ctx, "app/db", []contracts.Tag{{Key: "k", Value: "v"}})
			return err
		},
		"UntagSecret": func() error {
			_, err := svc.UntagSecret(ctx, "app/db", []string{"k"})
			return err
		},
	}
}

// requireUnchanged fails unless app/db is as put left it.
func requireUnchanged(t *testing.T, svc *dirimpl.Service) {
	t.Helper()
	detail, err := svc.DescribeSecret(contracts.Unchecked(context.Background()), "app/db")
	if err != nil {
		t.Fatal(err)
	}
	if detail.Description != "" || len(detail.Tags) != 0 || !detail.DeletedDate.IsZero() ||
		len(detail.VersionStages) != 1 {
		t.Fatalf("a refused operation changed the secret: %+v", detail)
	}
}

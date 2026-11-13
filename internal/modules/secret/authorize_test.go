package secret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/authz"
	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/smapi"
)

// describer is a store that only describes, from a fixed set of secrets
// keyed by the SecretId that finds them, running the context's check as a
// store does.
type describer struct {
	contracts.SecretsProvider
	secrets map[string]contracts.SecretDetail
}

func (d describer) DescribeSecret(ctx context.Context, id string) (*contracts.SecretDetail, error) {
	s, ok := d.secrets[id]
	var found *contracts.SecretDetail
	if ok {
		found = &s
	}
	if err := contracts.RunCheck(ctx, found); err != nil {
		return nil, err
	}
	if !ok {
		return nil, contracts.ErrSecretNotFound
	}
	return &s, nil
}

// checkRead runs GetSecretValue's check on secretID the way a handler does:
// through the store, with the guarded context.
func checkRead(ctx context.Context, m *Module, secretID string) error {
	sctx := m.guardSecret(ctx, "GetSecretValue", secretID, nil)
	_, err := m.secrets.DescribeSecret(sctx, secretID)
	return err
}

const (
	devARN  = "arn:aws:iam::000000000000:user/dev"
	ownBase = "arn:aws:secretsmanager:us-east-1:000000000000:secret:"
)

// moduleFor returns a Module over secrets, and a context whose request was
// signed by the user dev with the policy docs.
func moduleFor(
	t *testing.T,
	secrets map[string]contracts.SecretDetail,
	docs ...string,
) (*Module, context.Context) {
	t.Helper()
	az := authz.New("us-east-1", "000000000000")
	p := sigv4.Principal{
		AccountID: "000000000000", ARN: devARN, PrincipalARN: devARN,
		UserID: "AIDAEXAMPLEDEV00001", Type: sigv4.PrincipalTypeUser,
	}
	for _, d := range docs {
		p.Policies = append(p.Policies, json.RawMessage(d))
	}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r = r.WithContext(sigv4.NewContext(r.Context(), p))
	r, err := az.Attach(r)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	return &Module{secrets: describer{secrets: secrets}, authz: az}, r.Context()
}

func requireAccessDenied(t *testing.T, err error) {
	t.Helper()
	var apiErr *smapi.Error
	if !errors.As(err, &apiErr) || apiErr.Type != smapi.TypeAccessDenied {
		t.Fatalf("want AccessDeniedException, got %v", err)
	}
}

func TestADenyOnAnEscapedTagKeyStillApplies(t *testing.T) {
	// T is "T": the policy's key is aws:ResourceTag/env once parsed,
	// though its bytes do not contain that text. The tags are loaded
	// regardless, so the Deny applies.
	allowAll := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	deny := `{"Version":"2012-10-17","Statement":{"Effect":"Deny",` +
		`"Action":"secretsmanager:GetSecretValue","Resource":"*",` +
		`"Condition":{"StringEquals":{"aws:ResourceTag/env":"prod"}}}}`
	m, ctx := moduleFor(t, map[string]contracts.SecretDetail{
		"app/prod": {
			SecretRef: contracts.SecretRef{Name: "app/prod", ARN: ownBase + "app/prod-AbCdEf"},
			Tags:      []contracts.Tag{{Key: "env", Value: "prod"}},
		},
		"app/dev": {
			SecretRef: contracts.SecretRef{Name: "app/dev", ARN: ownBase + "app/dev-AbCdEf"},
			Tags:      []contracts.Tag{{Key: "env", Value: "dev"}},
		},
	}, allowAll, deny)

	err := checkRead(ctx, m, "app/prod")
	requireAccessDenied(t, err)
	if err = checkRead(ctx, m, "app/dev"); err != nil {
		t.Fatalf("the dev secret: %v", err)
	}
}

func TestAForeignARNIsNotFoundWithoutEvaluation(t *testing.T) {
	// The policy allows exactly the ARN the request names, in another
	// region; it is never evaluated, since that ARN names no secret here.
	foreign := "arn:aws:secretsmanager:eu-west-1:000000000000:secret:app/db-AbCdEf"
	other := "arn:aws:secretsmanager:us-east-1:999999999999:secret:app/db-AbCdEf"
	allow := `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
		`"Action":"secretsmanager:GetSecretValue","Resource":["` + foreign + `","` + other + `"]}}`
	m, ctx := moduleFor(t, nil, allow)

	for _, id := range []string{foreign, other} {
		err := checkRead(ctx, m, id)
		if !errors.Is(err, contracts.ErrSecretNotFound) {
			t.Fatalf("%s: want ErrSecretNotFound, got %v", id, err)
		}
	}
}

func TestAnExistingSecretIsCheckedOnTheStoresOwnARN(t *testing.T) {
	// A secret whose stored ARN carries another region, as after the
	// configured region changed, is checked on the ARN in the store's own
	// region with the stored suffix.
	allow := `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
		`"Action":"secretsmanager:GetSecretValue","Resource":"` + ownBase + `app/db-AbCdEf"}}`
	m, ctx := moduleFor(t, map[string]contracts.SecretDetail{
		"app/db": {SecretRef: contracts.SecretRef{
			Name: "app/db",
			ARN:  "arn:aws:secretsmanager:eu-west-1:000000000000:secret:app/db-AbCdEf",
		}},
	}, allow)

	if err := checkRead(ctx, m, "app/db"); err != nil {
		t.Fatalf("own ARN: %v", err)
	}
}

func TestStoredDuplicateTagKeysFailTheCheck(t *testing.T) {
	allowAll := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	m, ctx := moduleFor(t, map[string]contracts.SecretDetail{
		"app/db": {
			SecretRef: contracts.SecretRef{Name: "app/db", ARN: ownBase + "app/db-AbCdEf"},
			Tags:      []contracts.Tag{{Key: "env", Value: "dev"}, {Key: "env", Value: "prod"}},
		},
	}, allowAll)

	err := checkRead(ctx, m, "app/db")
	var apiErr *smapi.Error
	if err == nil || errors.As(err, &apiErr) {
		t.Fatalf("want an internal error, got %v", err)
	}
}

func TestTheFurtherChecksRunOnlyOnceTheRequestIsAllowed(t *testing.T) {
	// A caller denied everything learns nothing from TagResource of the tag
	// keys a secret holds: ENV, colliding by case with the stored env, is
	// answered like TEAM, and like a missing secret.
	denyAll := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}`
	secrets := map[string]contracts.SecretDetail{
		"app/db": {
			SecretRef: contracts.SecretRef{Name: "app/db", ARN: ownBase + "app/db-AbCdEf"},
			Tags:      []contracts.Tag{{Key: "env", Value: "dev"}},
		},
	}
	collides := func(adding string) contracts.Check {
		return func(found *contracts.SecretDetail) error {
			if found == nil {
				return nil
			}
			return contracts.CheckTagKeysAgainst([]contracts.Tag{{Key: adding}}, found.Tags)
		}
	}
	m, ctx := moduleFor(t, secrets, denyAll)
	for _, c := range []struct{ id, key string }{
		{"app/db", "ENV"}, {"app/db", "TEAM"}, {"app/none", "ENV"},
	} {
		sctx := m.guardSecret(ctx, "TagResource", c.id, nil, collides(c.key))
		_, err := m.secrets.DescribeSecret(sctx, c.id)
		requireAccessDenied(t, err)
	}

	// Allowed, the collision is reported.
	allowAll := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	m, ctx = moduleFor(t, secrets, allowAll)
	sctx := m.guardSecret(ctx, "TagResource", "app/db", nil, collides("ENV"))
	if _, err := m.secrets.DescribeSecret(sctx, "app/db"); !errors.Is(err,
		contracts.ErrDuplicateTagKeys) {
		t.Fatalf("allowed: want the collision, got %v", err)
	}
}

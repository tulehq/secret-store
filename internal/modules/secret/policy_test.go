package secret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/authz"
	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/smapi"
)

func requireType(t *testing.T, err error, typ string) {
	t.Helper()
	var apiErr *smapi.Error
	if !errors.As(err, &apiErr) || apiErr.Type != typ {
		t.Fatalf("want %s, got %v", typ, err)
	}
}

func ptr(s string) *string { return &s }

func TestCheckPolicyName(t *testing.T) {
	if err := checkPolicyName(nil, false); err != nil {
		t.Fatalf("absent: %v", err)
	}
	if err := checkPolicyName(ptr("default"), true); err != nil {
		t.Fatalf("default: %v", err)
	}
	requireType(t, checkPolicyName(ptr(""), false), smapi.TypeValidation)
	requireType(t, checkPolicyName(ptr(strings.Repeat("a", 65)), false), smapi.TypeValidation)
	requireType(t, checkPolicyName(ptr("no spaces"), false), smapi.TypeValidation)
	requireType(t, checkPolicyName(ptr("other_name-1"), false), smapi.TypeInvalidParameter)
	requireType(t, checkPolicyName(ptr("other_name-1"), true), smapi.TypeResourceNotFound)
}

func TestRequirePolicy(t *testing.T) {
	m, _ := moduleFor(t, nil)
	valid := `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
		`"Principal":{"AWS":"111122223333"},"Action":"secretsmanager:GetSecretValue",` +
		`"Resource":"*"}}`
	if got, err := m.requirePolicy(&valid); err != nil || got != valid {
		t.Fatalf("valid: %q, %v", got, err)
	}

	_, err := m.requirePolicy(nil)
	requireType(t, err, smapi.TypeInvalidParameter)
	_, err = m.requirePolicy(ptr(""))
	requireType(t, err, smapi.TypeValidation)
	_, err = m.requirePolicy(ptr(`{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
		`"Action":"*","Resource":"*"}}`))
	requireType(t, err, smapi.TypeMalformedPolicy)

	// The limit counts characters: 20480 two-byte characters pass the length
	// check (and fail to parse), one more does not.
	fits := `"` + strings.Repeat("é", maxPolicyLen-2) + `"`
	_, err = m.requirePolicy(&fits)
	requireType(t, err, smapi.TypeMalformedPolicy)
	over := `"` + strings.Repeat("é", maxPolicyLen-1) + `"`
	_, err = m.requirePolicy(&over)
	requireType(t, err, smapi.TypeValidation)
}

func TestTheStoredResourcePolicyIsEvaluated(t *testing.T) {
	deny := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":"*",` +
		`"Action":"secretsmanager:GetSecretValue","Resource":"*"}}`
	m, ctx := moduleFor(t, map[string]contracts.SecretDetail{
		"app/db": {SecretRef: contracts.SecretRef{Name: "app/db", ARN: ownBase + "app/db-AbCdEf"}},
		"app/locked": {
			SecretRef: contracts.SecretRef{
				Name: "app/locked", ARN: ownBase + "app/locked-AbCdEf",
			},
			ResourcePolicy: deny,
		},
	}, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)

	if err := checkRead(ctx, m, "app/db"); err != nil {
		t.Fatalf("no resource policy: %v", err)
	}
	err := checkRead(ctx, m, "app/locked")
	requireAccessDenied(t, err)
	if !strings.HasSuffix(err.Error(), "with an explicit deny in a resource-based policy") {
		t.Fatalf("message: %v", err)
	}
}

const partnerARN = "arn:aws:iam::111122223333:user/partner"

// partnerModule is moduleFor with the user partner of another account
// signing, with the policy docs.
func partnerModule(
	t *testing.T,
	secrets map[string]contracts.SecretDetail,
	docs ...string,
) (*Module, context.Context) {
	t.Helper()
	az := authz.New("us-east-1", "000000000000")
	p := sigv4.Principal{
		AccountID: "111122223333", ARN: partnerARN, PrincipalARN: partnerARN,
		UserID: "AIDAEXAMPLEPARTNER01", Type: sigv4.PrincipalTypeUser,
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

func TestAnotherAccountNamingASecretByNameFindsNothing(t *testing.T) {
	grantPartner := `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
		`"Principal":{"AWS":"` + partnerARN + `"},"Action":"*","Resource":"*"}}`
	denyAll := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":"*",` +
		`"Action":"*","Resource":"*"}}`
	secrets := map[string]contracts.SecretDetail{
		"app/shared": {
			SecretRef: contracts.SecretRef{
				Name: "app/shared",
				ARN:  ownBase + "app/shared-AbCdEf",
			},
			ResourcePolicy: grantPartner,
		},
		"app/locked": {
			SecretRef: contracts.SecretRef{
				Name: "app/locked",
				ARN:  ownBase + "app/locked-AbCdEf",
			},
			ResourcePolicy: denyAll,
		},
	}
	// The describer finds a secret by the SecretId it is keyed by.
	secrets[ownBase+"app/shared-AbCdEf"] = secrets["app/shared"]
	allowAll := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	m, ctx := partnerModule(t, secrets, allowAll)

	// By ARN the store's secret is reached through its policy.
	if err := checkRead(ctx, m, ownBase+"app/shared-AbCdEf"); err != nil {
		t.Fatalf("by ARN: %v", err)
	}
	// By name it is a secret of the caller's own account, which the store
	// does not hold, whatever the store's secret of that name allows or
	// denies: neither its grant nor its Deny shows.
	for _, name := range []string{"app/shared", "app/locked", "app/missing"} {
		err := checkRead(ctx, m, name)
		if !errors.Is(err, contracts.ErrSecretNotFound) {
			t.Errorf("%s by name: want not found, got %v", name, err)
		}
	}

	// Its identity policies are still evaluated, on its own account's ARN.
	m, ctx = partnerModule(t, secrets)
	err := checkRead(ctx, m, "app/shared")
	requireAccessDenied(t, err)
	if !strings.Contains(err.Error(), "because no identity-based policy allows") {
		t.Fatalf("message: %v", err)
	}
}

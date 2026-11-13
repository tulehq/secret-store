package secret

import (
	"errors"
	"strings"
	"testing"

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

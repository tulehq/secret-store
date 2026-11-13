package authz

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"tule.dev/policy"
	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/smapi"
)

const (
	partnerARN  = "arn:aws:iam::111122223333:user/partner"
	pathRoleARN = "arn:aws:iam::000000000000:role/team/reader"
	pathSession = "arn:aws:sts::000000000000:assumed-role/reader/s1"
)

func partner(docs ...string) sigv4.Principal {
	p := sigv4.Principal{
		AccountID: "111122223333", ARN: partnerARN, PrincipalARN: partnerARN,
		UserID: "AIDAEXAMPLEPARTNER01", Type: sigv4.PrincipalTypeUser,
	}
	for _, d := range docs {
		p.Policies = append(p.Policies, json.RawMessage(d))
	}
	return p
}

func pathRoleSession(docs ...string) sigv4.Principal {
	p := sigv4.Principal{
		AccountID: "000000000000", ARN: pathSession, PrincipalARN: pathRoleARN,
		UserID: "AROAEXAMPLEREADER001:s1", Type: sigv4.PrincipalTypeAssumedRole,
		Tags: map[string]string{"team": "core"},
	}
	for _, d := range docs {
		p.Policies = append(p.Policies, json.RawMessage(d))
	}
	return p
}

// grant is a resource policy statement of effect for principal on
// GetSecretValue, with an optional condition.
func grant(effect, principal, condition string) string {
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"` + effect + `",` +
		`"Principal":{"AWS":"` + principal + `"},` +
		`"Action":"secretsmanager:GetSecretValue","Resource":"*"`
	if condition != "" {
		doc += `,"Condition":` + condition
	}
	return doc + `}}`
}

func withPolicy(doc string) Request {
	req := getValue(secretARN, "app/db")
	req.Policy = doc
	return req
}

func denied(principal, reason string) string {
	return "User: " + principal + " is not authorized to perform: " +
		"secretsmanager:GetSecretValue on resource: app/db " + reason
}

const getAction = "secretsmanager:GetSecretValue"

func TestCallerOfCarriesThePrincipalsFields(t *testing.T) {
	got := callerOf(pathRoleSession())
	want := policy.Caller{
		AccountID: "000000000000", ARN: pathSession, PrincipalARN: pathRoleARN,
		UserID: "AROAEXAMPLEREADER001:s1", Type: policy.PrincipalTypeAssumedRole,
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestReasonMessages(t *testing.T) {
	cases := map[policy.Reason]string{
		policy.IdentityDeny:    "with an explicit deny in an identity-based policy",
		policy.ResourceDeny:    "with an explicit deny in a resource-based policy",
		policy.NoIdentityAllow: "because no identity-based policy allows the " + getAction + " action",
		policy.NoResourceAllow: "because no resource-based policy allows the " + getAction + " action",
	}
	for reason, msg := range cases {
		err := decide(policy.Authorization{Decision: policy.ImplicitDeny, Reason: reason},
			userARN, getValue(secretARN, "app/db"))
		requireDenied(t, err, denied(userARN, msg))
	}
	if err := decide(policy.Authorization{Decision: policy.Allow}, userARN,
		getValue(secretARN, "app/db")); err != nil {
		t.Fatalf("allow: %v", err)
	}
	err := decide(policy.Authorization{Decision: policy.ImplicitDeny}, userARN,
		getValue(secretARN, "app/db"))
	var apiErr *smapi.Error
	if err == nil || errors.As(err, &apiErr) {
		t.Fatalf("a deny without a reason: want an internal error, got %v", err)
	}
}

func TestACrossAccountPrincipalNeedsBothPolicies(t *testing.T) {
	a := New("us-east-1", "000000000000")
	allowed := attached(t, a, partner(allow("secretsmanager:*", "*"))).Context()

	if err := a.Check(allowed, withPolicy(grant("Allow", partnerARN, ""))); err != nil {
		t.Fatalf("granted by both: %v", err)
	}
	// Its account's root ARN grants it too, with its identity Allow.
	if err := a.Check(allowed, withPolicy(
		grant("Allow", "arn:aws:iam::111122223333:root", ""))); err != nil {
		t.Fatalf("granted through its account: %v", err)
	}
	err := a.Check(allowed, withPolicy(grant("Allow", userARN, "")))
	requireDenied(t, err, denied(partnerARN,
		"because no resource-based policy allows the "+getAction+" action"))

	// The resource grant alone is not enough across accounts.
	err = a.Check(attached(t, a, partner()).Context(), withPolicy(grant("Allow", partnerARN, "")))
	requireDenied(t, err, denied(partnerARN,
		"because no identity-based policy allows the "+getAction+" action"))
}

func TestAResourceDenyBeatsAnIdentityAllow(t *testing.T) {
	a := New("us-east-1", "000000000000")
	ctx := attached(t, a, user(allow("secretsmanager:*", "*"))).Context()
	err := a.Check(ctx, withPolicy(grant("Deny", userARN, "")))
	requireDenied(t, err, denied(userARN, "with an explicit deny in a resource-based policy"))
}

func TestASameAccountUserNamedByTheResourcePolicyNeedsNoIdentityPolicy(t *testing.T) {
	a := New("us-east-1", "000000000000")
	ctx := attached(t, a, user()).Context()
	if err := a.Check(ctx, withPolicy(grant("Allow", userARN, ""))); err != nil {
		t.Fatalf("direct grant: %v", err)
	}
	// A grant to the account delegates to its identity policies.
	err := a.Check(ctx, withPolicy(grant("Allow", "000000000000", "")))
	requireDenied(t, err, denied(userARN,
		"because no identity-based policy allows the "+getAction+" action"))
	ctx = attached(t, a, user(allow(getAction, "*"))).Context()
	if err = a.Check(ctx, withPolicy(grant("Allow", "000000000000", ""))); err != nil {
		t.Fatalf("account grant with an identity Allow: %v", err)
	}
}

func TestARoleSessionMatchesItsRoleARNWithAPath(t *testing.T) {
	a := New("us-east-1", "000000000000")
	ctx := attached(t, a, pathRoleSession()).Context()
	if err := a.Check(ctx, withPolicy(grant("Allow", pathRoleARN, ""))); err != nil {
		t.Fatalf("role ARN with its path: %v", err)
	}
	// aws:PrincipalArn is the role's ARN with its path.
	cond := `{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::000000000000:role/team/*"}}`
	if err := a.Check(ctx, withPolicy(grant("Allow", "*", cond))); err != nil {
		t.Fatalf("condition on the path: %v", err)
	}
	ctx = attached(t, a, pathRoleSession(allow("secretsmanager:*", "*"))).Context()
	err := a.Check(ctx, withPolicy(grant("Deny", "*", cond)))
	requireDenied(t, err, denied(pathSession, "with an explicit deny in a resource-based policy"))
}

func TestAPrincipalTagReachesTheConditions(t *testing.T) {
	a := New("us-east-1", "000000000000")
	ctx := attached(t, a, pathRoleSession()).Context()
	if err := a.Check(ctx, withPolicy(grant("Allow", "*",
		`{"StringEquals":{"aws:PrincipalTag/team":"core"}}`))); err != nil {
		t.Fatalf("matching tag: %v", err)
	}
	err := a.Check(ctx, withPolicy(grant("Allow", "*",
		`{"StringEquals":{"aws:PrincipalTag/team":"ops"}}`)))
	requireDenied(t, err, denied(pathSession,
		"because no identity-based policy allows the "+getAction+" action"))
}

func TestAStoredPolicyThatDoesNotParseFailsClosed(t *testing.T) {
	a := New("us-east-1", "000000000000")
	ctx := attached(t, a, user(allow("*", "*"))).Context()
	err := a.Check(ctx, withPolicy(`{"Version":"2012-10-17","Statement":{"Effect":"Allow",`+
		`"Action":"*","Resource":"*"}}`))
	var apiErr *smapi.Error
	if err == nil || errors.As(err, &apiErr) {
		t.Fatalf("want an internal error, got %v", err)
	}
}

func TestCallersAccountChecksAsTheCallersOwn(t *testing.T) {
	a := New("us-east-1", "000000000000")
	ctx := attached(t, a, partner(allow("secretsmanager:BatchGetSecretValue", "*"))).Context()
	req := Request{
		Operation: "BatchGetSecretValue", Action: "secretsmanager:BatchGetSecretValue",
		Resource: "*", Shown: "*",
	}
	err := a.Check(ctx, req)
	requireDenied(t, err, "User: "+partnerARN+" is not authorized to perform: "+
		"secretsmanager:BatchGetSecretValue on resource: * because no resource-based "+
		"policy allows the secretsmanager:BatchGetSecretValue action")
	req.CallersAccount = true
	if err = a.Check(ctx, req); err != nil {
		t.Fatalf("on the caller's account: %v", err)
	}
}

func TestRootAndTypeMustAgree(t *testing.T) {
	// Every principal is of the store's own account, where a consistent
	// root would skip evaluation: the check runs before that shortcut.
	a := New("us-east-1", "000000000000")
	const rootARN = "arn:aws:iam::000000000000:root"
	for name, p := range map[string]sigv4.Principal{
		"an account principal that is not root": {
			AccountID: "000000000000", ARN: rootARN, PrincipalARN: rootARN,
			UserID: "000000000000", Type: sigv4.PrincipalTypeAccount,
		},
		"a root user principal of the store's account": {
			AccountID: "000000000000", ARN: userARN, PrincipalARN: userARN,
			UserID: "AIDAEXAMPLEUSER00001", Type: sigv4.PrincipalTypeUser, Root: true,
		},
		"a root principal without a type": {
			AccountID: "000000000000", ARN: rootARN, Root: true,
		},
	} {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r = r.WithContext(sigv4.NewContext(r.Context(), p))
		_, err := a.Attach(r)
		var apiErr *smapi.Error
		if err == nil || errors.As(err, &apiErr) {
			t.Errorf("%s: want an internal error, got %v", name, err)
		}
	}
}

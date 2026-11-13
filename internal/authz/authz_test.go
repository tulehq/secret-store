package authz

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/smapi"
)

const (
	userARN    = "arn:aws:iam::000000000000:user/team/dev"
	sessionARN = "arn:aws:sts::000000000000:assumed-role/reader/s1"
	secretARN  = "arn:aws:secretsmanager:us-east-1:000000000000:secret:app/db-AbCdEf"
)

// attached returns a request signed, as far as Attach can tell, by p.
func attached(t *testing.T, a *Authorizer, p sigv4.Principal) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "192.0.2.10:54321"
	r = r.WithContext(sigv4.NewContext(r.Context(), p))
	out, err := a.Attach(r)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	return out
}

func user(docs ...string) sigv4.Principal {
	p := sigv4.Principal{AccountID: "000000000000", ARN: userARN, AccessKeyID: "AKIAEXAMPLE"}
	for _, d := range docs {
		p.Policies = append(p.Policies, json.RawMessage(d))
	}
	return p
}

func allow(action, resource string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow",`+
		`"Action":%q,"Resource":%q}}`, action, resource)
}

func getValue(resource, shown string) Request {
	return Request{
		Operation: "GetSecretValue", Action: "secretsmanager:GetSecretValue",
		Resource: resource, Shown: shown,
	}
}

// requireDenied fails unless err is AccessDeniedException with message msg.
func requireDenied(t *testing.T, err error, msg string) {
	t.Helper()
	var apiErr *smapi.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("want AccessDeniedException, got %v", err)
	}
	if apiErr.Type != smapi.TypeAccessDenied || apiErr.Status != http.StatusBadRequest {
		t.Fatalf("want a 400 AccessDeniedException, got %d %s", apiErr.Status, apiErr.Type)
	}
	if apiErr.Message != msg {
		t.Fatalf("message:\n got %s\nwant %s", apiErr.Message, msg)
	}
}

func TestRootIsAllowedWithoutPolicies(t *testing.T) {
	a := New("us-east-1", "000000000000")
	r := attached(
		t,
		a,
		sigv4.Principal{
			AccountID: "000000000000",
			ARN:       "arn:aws:iam::000000000000:root",
			Root:      true,
		},
	)

	if !IsRoot(r.Context()) {
		t.Fatal("IsRoot is false for the root principal")
	}
	if err := a.Check(r.Context(), getValue(secretARN, "app/db")); err != nil {
		t.Fatalf("root: %v", err)
	}
}

func TestAStaticKeyIsRoot(t *testing.T) {
	// Without an identity endpoint the static key signs every request, and
	// its principal is root, so nothing is ever evaluated.
	key, err := sigv4.NewStaticKey(sigv4.StaticKeyConfig{
		AccessKeyID: "test", SecretAccessKey: "test", AccountID: "000000000000",
	})
	if err != nil {
		t.Fatal(err)
	}
	k, err := key.SigningKey(t.Context(), sigv4.Scope{AccessKeyID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	a := New("us-east-1", "000000000000")
	r := attached(t, a, k.Principal)
	if err = a.Check(r.Context(), getValue(secretARN, "app/db")); err != nil {
		t.Fatalf("static key: %v", err)
	}
}

func TestARootPrincipalOfAnotherAccountIsRefused(t *testing.T) {
	a := New("us-east-1", "000000000000")
	const otherRoot = "arn:aws:iam::111122223333:root"
	r := attached(t, a, sigv4.Principal{AccountID: "111122223333", ARN: otherRoot, Root: true})

	if IsRoot(r.Context()) {
		t.Fatal("IsRoot is true for another account's root")
	}
	err := a.Check(r.Context(), getValue(secretARN, "app/db"))
	requireDenied(t, err, "User: "+otherRoot+" is not authorized to perform: "+
		"secretsmanager:GetSecretValue on resource: app/db because no identity-based "+
		"policy allows the secretsmanager:GetSecretValue action")
}

func TestTheStaticKeyOfANonDefaultAccountIsRoot(t *testing.T) {
	key, err := sigv4.NewStaticKey(sigv4.StaticKeyConfig{
		AccessKeyID: "test", SecretAccessKey: "test", AccountID: "444455556666",
	})
	if err != nil {
		t.Fatal(err)
	}
	k, err := key.SigningKey(t.Context(), sigv4.Scope{AccessKeyID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	a := New("us-east-1", "444455556666")
	r := attached(t, a, k.Principal)
	if err = a.Check(r.Context(), getValue(
		"arn:aws:secretsmanager:us-east-1:444455556666:secret:app/db-AbCdEf",
		"app/db",
	)); err != nil {
		t.Fatalf("static key: %v", err)
	}
}

func TestAPrincipalWithoutPoliciesIsDenied(t *testing.T) {
	a := New("us-east-1", "000000000000")
	r := attached(t, a, user())

	if IsRoot(r.Context()) {
		t.Fatal("IsRoot is true for a user")
	}
	err := a.Check(r.Context(), getValue(secretARN, "app/db"))
	requireDenied(t, err, "User: "+userARN+" is not authorized to perform: "+
		"secretsmanager:GetSecretValue on resource: app/db because no identity-based "+
		"policy allows the secretsmanager:GetSecretValue action")
}

func TestAnAllowAllowsAndAnExplicitDenyWins(t *testing.T) {
	a := New("us-east-1", "000000000000")
	scoped := allow("secretsmanager:GetSecretValue",
		"arn:aws:secretsmanager:us-east-1:000000000000:secret:app/db-??????")

	r := attached(t, a, user(scoped))
	if err := a.Check(r.Context(), getValue(secretARN, "app/db")); err != nil {
		t.Fatalf("allowed secret: %v", err)
	}
	other := "arn:aws:secretsmanager:us-east-1:000000000000:secret:app/other-AbCdEf"
	err := a.Check(r.Context(), getValue(other, other))
	requireDenied(t, err, "User: "+userARN+" is not authorized to perform: "+
		"secretsmanager:GetSecretValue on resource: "+other+" because no identity-based "+
		"policy allows the secretsmanager:GetSecretValue action")

	deny := `{"Version":"2012-10-17","Statement":{"Effect":"Deny",` +
		`"Action":"secretsmanager:Get*","Resource":"*"}}`
	r = attached(t, a, user(allow("secretsmanager:*", "*"), deny))
	err = a.Check(r.Context(), getValue(secretARN, "app/db"))
	requireDenied(t, err, "User: "+userARN+" is not authorized to perform: "+
		"secretsmanager:GetSecretValue on resource: app/db with an explicit deny in an "+
		"identity-based policy")
}

func TestAResourceNamedByAUserNameVariableMatches(t *testing.T) {
	a := New("us-east-1", "000000000000")
	r := attached(t, a, user(allow("secretsmanager:GetSecretValue",
		"arn:aws:secretsmanager:*:*:secret:home/${aws:username}/*")))

	mine := "arn:aws:secretsmanager:us-east-1:000000000000:secret:home/dev/key-AbCdEf"
	if err := a.Check(r.Context(), getValue(mine, mine)); err != nil {
		t.Fatalf("own secret: %v", err)
	}
	theirs := "arn:aws:secretsmanager:us-east-1:000000000000:secret:home/ops/key-AbCdEf"
	if err := a.Check(r.Context(), getValue(theirs, theirs)); err == nil {
		t.Fatal("another user's secret was allowed")
	}
}

func TestServiceKeysReachTheConditions(t *testing.T) {
	a := New("us-east-1", "000000000000")
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
		`"Action":"secretsmanager:GetSecretValue","Resource":"*",` +
		`"Condition":{"StringEquals":{"secretsmanager:ResourceTag/env":"dev",` +
		`"aws:ResourceTag/team":"core","secretsmanager:SecretPrimaryRegion":"us-east-1",` +
		`"secretsmanager:SecretId":"` + secretARN + `"}}}}`
	r := attached(t, a, user(doc))

	req := getValue(secretARN, "app/db")
	req.Keys = a.SecretKeys(secretARN, map[string]string{"env": "dev", "team": "core"})
	if err := a.Check(r.Context(), req); err != nil {
		t.Fatalf("matching tags: %v", err)
	}
	req.Keys = a.SecretKeys(secretARN, map[string]string{"env": "prod", "team": "core"})
	if err := a.Check(r.Context(), req); err == nil {
		t.Fatal("a secret tagged env=prod was allowed")
	}
}

func TestRequestTagsReachTheConditions(t *testing.T) {
	a := New("us-east-1", "000000000000")
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
		`"Action":"secretsmanager:TagResource","Resource":"*",` +
		`"Condition":{"StringEquals":{"aws:RequestTag/env":"dev"},` +
		`"ForAllValues:StringEquals":{"aws:TagKeys":["env","team"]}}}}`
	r := attached(t, a, user(doc))
	tag := func(tags ...smapi.Tag) error {
		return a.Check(r.Context(), Request{
			Operation: "TagResource", Action: "secretsmanager:TagResource",
			Resource: secretARN, Shown: "app/db", Keys: TagKeys(tags),
		})
	}

	if err := tag(
		smapi.Tag{Key: "env", Value: "dev"},
		smapi.Tag{Key: "team", Value: "a"},
	); err != nil {
		t.Fatalf("allowed tags: %v", err)
	}
	if err := tag(smapi.Tag{Key: "env", Value: "prod"}); err == nil {
		t.Fatal("env=prod was allowed")
	}
	if err := tag(
		smapi.Tag{Key: "env", Value: "dev"},
		smapi.Tag{Key: "owner", Value: "x"},
	); err == nil {
		t.Fatal("an unlisted tag key was allowed")
	}
}

func TestAKeyTheMappingDoesNotListIsAWiringError(t *testing.T) {
	a := New("us-east-1", "000000000000")
	r := attached(t, a, user(allow("*", "*")))

	req := getValue(secretARN, "app/db")
	req.Keys = map[string][]string{"secretsmanager:Name": {"app/db"}}
	err := a.Check(r.Context(), req)
	var apiErr *smapi.Error
	if err == nil || errors.As(err, &apiErr) {
		t.Fatalf("want an internal error, got %v", err)
	}

	err = a.Check(r.Context(), Request{
		Operation: "GetSecretValue", Action: "secretsmanager:DeleteSecret",
		Resource: secretARN, Shown: "app/db",
	})
	if err == nil || errors.As(err, &apiErr) {
		t.Fatalf("want an internal error for an unmapped action, got %v", err)
	}
}

func TestCheckFailsClosedWithoutAttach(t *testing.T) {
	a := New("us-east-1", "000000000000")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	if err := a.Check(r.Context(), getValue(secretARN, "app/db")); err == nil {
		t.Fatal("a request Attach has not seen was allowed")
	}
	if IsRoot(r.Context()) {
		t.Fatal("a request Attach has not seen is root")
	}
	if _, err := a.Attach(r); err == nil {
		t.Fatal("Attach accepted a request without a principal")
	}
}

func TestAPolicyThatDoesNotParseFailsAttach(t *testing.T) {
	a := New("us-east-1", "000000000000")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r = r.WithContext(sigv4.NewContext(r.Context(), user(`{"Statement":[]}`)))
	if _, err := a.Attach(r); err == nil {
		t.Fatal("Attach accepted a policy that does not parse")
	}
}

func TestTooMuchContextIsRefused(t *testing.T) {
	a := New("us-east-1", "000000000000")
	r := attached(t, a, user(allow("*", "*")))

	tags := make([]smapi.Tag, maxKeyValues+1)
	for i := range tags {
		tags[i] = smapi.Tag{Key: fmt.Sprintf("k%d", i), Value: "v"}
	}
	err := a.Check(r.Context(), Request{
		Operation: "TagResource", Action: "secretsmanager:TagResource",
		Resource: secretARN, Shown: "app/db", Keys: TagKeys(tags),
	})
	var apiErr *smapi.Error
	if !errors.As(err, &apiErr) || apiErr.Type != smapi.TypeInvalidParameter {
		t.Fatalf("want InvalidParameterException, got %v", err)
	}

	req := getValue(secretARN, "app/db")
	req.Keys = map[string][]string{
		"secretsmanager:VersionStage": {strings.Repeat("x", maxKeyValueLen+1)},
	}
	err = a.Check(r.Context(), req)
	if !errors.As(err, &apiErr) || apiErr.Type != smapi.TypeInvalidParameter {
		t.Fatalf("want InvalidParameterException for a long value, got %v", err)
	}
}

func TestGlobalKeys(t *testing.T) {
	fixed := time.Date(2026, 11, 13, 9, 30, 0, 0, time.UTC)
	now = func() time.Time { return fixed }
	t.Cleanup(func() { now = time.Now })

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "192.0.2.10:54321"

	got := globalKeys(r, user(), "us-east-1")
	want := map[string][]string{
		"aws:RequestedRegion":  {"us-east-1"},
		"aws:CurrentTime":      {"2026-11-13T09:30:00Z"},
		"aws:EpochTime":        {"1794562200"},
		"aws:SecureTransport":  {"false"},
		"aws:SourceIp":         {"192.0.2.10"},
		"aws:PrincipalAccount": {"000000000000"},
		"aws:PrincipalArn":     {userARN},
		"aws:username":         {"dev"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("user keys:\n got %v\nwant %v", got, want)
	}

	r.TLS = &tls.ConnectionState{}
	r.RemoteAddr = "[2001:db8::1]:443"
	session := sigv4.Principal{AccountID: "000000000000", ARN: sessionARN}
	got = globalKeys(r, session, "us-east-1")
	want = map[string][]string{
		"aws:RequestedRegion":  {"us-east-1"},
		"aws:CurrentTime":      {"2026-11-13T09:30:00Z"},
		"aws:EpochTime":        {"1794562200"},
		"aws:SecureTransport":  {"true"},
		"aws:SourceIp":         {"2001:db8::1"},
		"aws:PrincipalAccount": {"000000000000"},
		"aws:PrincipalArn":     {"arn:aws:iam::000000000000:role/reader"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("session keys:\n got %v\nwant %v", got, want)
	}
}

func TestRequestedRegionIsTheStoresRegion(t *testing.T) {
	// The store is in us-east-1, so a Deny on us-east-1 applies, whatever
	// region the request was signed for (the e2e test signs for another).
	a := New("us-east-1", "000000000000")
	deny := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*",` +
		`"Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}}`
	r := attached(t, a, user(allow("*", "*"), deny))
	err := a.Check(r.Context(), getValue(secretARN, "app/db"))
	requireDenied(t, err, "User: "+userARN+" is not authorized to perform: "+
		"secretsmanager:GetSecretValue on resource: app/db with an explicit deny in an "+
		"identity-based policy")
}

func TestASourceIpConditionIsHonored(t *testing.T) {
	a := New("us-east-1", "000000000000")
	doc := func(cidr string) string {
		return `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
			`"Action":"secretsmanager:GetSecretValue","Resource":"*",` +
			`"Condition":{"IpAddress":{"aws:SourceIp":"` + cidr + `"}}}}`
	}
	if err := a.Check(attached(t, a, user(doc("192.0.2.0/24"))).Context(),
		getValue(secretARN, "app/db")); err != nil {
		t.Fatalf("matching address: %v", err)
	}
	if err := a.Check(attached(t, a, user(doc("203.0.113.0/24"))).Context(),
		getValue(secretARN, "app/db")); err == nil {
		t.Fatal("another address was allowed")
	}
}

func TestPrincipalARN(t *testing.T) {
	cases := map[string]string{
		userARN:    userARN,
		sessionARN: "arn:aws:iam::000000000000:role/reader",
		"arn:aws:sts::000000000000:assumed-role/reader": "",
		"arn:aws:sts::000000000000:federated-user/x":    "",
		"not-an-arn": "",
	}
	for in, want := range cases {
		got, ok := principalARN(in)
		if got != want || ok != (want != "") {
			t.Errorf("principalARN(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestMissingSecretARN(t *testing.T) {
	a := New("eu-west-1", "111122223333")
	cases := map[string]string{
		"app/db": "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db",
		"arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db-AbCdEf": "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db-AbCdEf",
		"arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db":        "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db",
		// Another region, account or partition names no secret here.
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:app/db-AbCdEf":    "",
		"arn:aws:secretsmanager:eu-west-1:999999999999:secret:app/db-AbCdEf":    "",
		"arn:aws-cn:secretsmanager:eu-west-1:111122223333:secret:app/db-AbCdEf": "",
		"arn:aws:secretsmanager:eu-west-1:111122223333:secret:":                 "",
		"arn:aws:secretsmanager:eu-west-1:111122223333:other:app/db":            "",
	}
	for in, want := range cases {
		got, ok := a.MissingSecretARN(in)
		if got != want || ok != (want != "") {
			t.Errorf("MissingSecretARN(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestSecretARNIsRebuiltFromTheStoresOwnFields(t *testing.T) {
	a := New("eu-west-1", "111122223333")
	got, err := a.SecretARN("app/db",
		"arn:aws:secretsmanager:us-east-1:000000000000:secret:app/db-AbCdEf")
	if err != nil {
		t.Fatal(err)
	}
	if want := "arn:aws:secretsmanager:eu-west-1:111122223333:secret:app/db-AbCdEf"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if _, err = a.SecretARN("app/db", "app/db"); err == nil {
		t.Fatal("a stored ARN without a suffix was accepted")
	}
}

func TestACrossAccountPrincipalIsDenied(t *testing.T) {
	a := New("us-east-1", "000000000000")
	const memberARN = "arn:aws:sts::111122223333:assumed-role/OrganizationAccountAccessRole/s"
	member := func(docs ...string) sigv4.Principal {
		p := sigv4.Principal{AccountID: "111122223333", ARN: memberARN}
		for _, d := range docs {
			p.Policies = append(p.Policies, json.RawMessage(d))
		}
		return p
	}

	// Its identity policies allow it, but no resource-based policy can.
	err := a.Check(attached(t, a, member(allow("*", "*"))).Context(), getValue(secretARN, "app/db"))
	requireDenied(t, err, "User: "+memberARN+" is not authorized to perform: "+
		"secretsmanager:GetSecretValue on resource: app/db because no resource-based "+
		"policy allows the secretsmanager:GetSecretValue action")

	err = a.Check(attached(t, a, member()).Context(), getValue(secretARN, "app/db"))
	requireDenied(t, err, "User: "+memberARN+" is not authorized to perform: "+
		"secretsmanager:GetSecretValue on resource: app/db because no identity-based "+
		"policy allows the secretsmanager:GetSecretValue action")

	deny := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}`
	err = a.Check(attached(t, a, member(allow("*", "*"), deny)).Context(),
		getValue(secretARN, "app/db"))
	requireDenied(t, err, "User: "+memberARN+" is not authorized to perform: "+
		"secretsmanager:GetSecretValue on resource: app/db with an explicit deny in an "+
		"identity-based policy")
}

func TestAParsedPolicyIsCached(t *testing.T) {
	c := newDocCache(2)
	doc := []byte(allow("secretsmanager:GetSecretValue", "*"))

	first, err := c.get(doc)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.get(doc)
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatal("the same document was parsed twice")
	}

	if _, err = c.get([]byte(`{"Statement":[]}`)); err == nil {
		t.Fatal("a document that does not parse was accepted")
	}
	if len(c.docs) != 1 {
		t.Fatal("a document that does not parse was cached")
	}
}

func TestTheCacheIsBounded(t *testing.T) {
	c := newDocCache(2)
	first := []byte(allow("secretsmanager:GetSecretValue", "*"))
	if _, err := c.get(first); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if _, err := c.get([]byte(allow("secretsmanager:GetSecretValue",
			fmt.Sprintf("arn:aws:secretsmanager:*:*:secret:%d", i)))); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.docs) != 2 || len(c.order) != 2 {
		t.Fatalf("the cache holds %d documents (%d in order), want 2", len(c.docs), len(c.order))
	}
	if _, ok := c.docs[sha256.Sum256(first)]; ok {
		t.Fatal("the oldest document was not evicted")
	}
}

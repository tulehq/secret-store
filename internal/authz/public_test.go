package authz

import (
	"errors"
	"net/http"
	"testing"

	"tule.dev/secret-store/internal/smapi"
)

func TestParseResourcePolicy(t *testing.T) {
	a := New("us-east-1", "000000000000")
	if err := a.ParseResourcePolicy(grant("Allow", partnerARN, "")); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
	// Any Sid string unique in the policy, as tule.dev/policy v0.2.1 accepts.
	sid := `{"Version":"2012-10-17","Statement":{"Sid":"read only, partner","Effect":"Allow",` +
		`"Principal":{"AWS":"` + partnerARN + `"},"Action":"secretsmanager:GetSecretValue",` +
		`"Resource":"*"}}`
	if err := a.ParseResourcePolicy(sid); err != nil {
		t.Fatalf("a Sid with spaces: %v", err)
	}
	for _, doc := range []string{
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		`not json`,
		grant("Allow", "arn:aws:iam::111122223333:group/admins", ""),
	} {
		err := a.ParseResourcePolicy(doc)
		var apiErr *smapi.Error
		if !errors.As(err, &apiErr) || apiErr.Type != smapi.TypeMalformedPolicy ||
			apiErr.Status != http.StatusBadRequest || apiErr.Message == "" {
			t.Errorf("%s: want MalformedPolicyDocumentException, got %v", doc, err)
		}
	}
}

func stmt(effect, principal, condition string) string {
	s := `{"Effect":"` + effect + `","Principal":` + principal +
		`,"Action":"secretsmanager:*","Resource":"*"`
	if condition != "" {
		s += `,"Condition":` + condition
	}
	return s + `}`
}

func doc(stmts ...string) string {
	out := `{"Version":"2012-10-17","Statement":[`
	for i, s := range stmts {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out + `]}`
}

var broadCases = []struct {
	name  string
	doc   string
	broad bool
}{
	{"star", doc(stmt("Allow", `"*"`, "")), true},
	{"AWS star", doc(stmt("Allow", `{"AWS":"*"}`, "")), true},
	{"star among others", doc(stmt("Allow", `{"AWS":["`+partnerARN+`","*"]}`, "")), true},
	{"single statement object", `{"Version":"2012-10-17","Statement":` +
		stmt("Allow", `"*"`, "") + `}`, true},
	{"fixed principal", doc(stmt("Allow", `{"AWS":"`+partnerARN+`"}`, "")), false},
	{"account", doc(stmt("Allow", `{"AWS":"111122223333"}`, "")), false},
	{"deny star", doc(stmt("Deny", `"*"`, "")), false},
	{"org ID", doc(stmt("Allow", `"*"`,
		`{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}`)), false},
	{"key in another case", doc(stmt("Allow", `"*"`,
		`{"StringEquals":{"AWS:principalorgid":"o-abc123"}}`)), false},
	{"escaped key", doc(stmt("Allow", `"*"`,
		`{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}`)), false},
	{"wildcard value", doc(stmt("Allow", `"*"`,
		`{"StringLike":{"aws:PrincipalOrgID":"o-*"}}`)), true},
	{"policy variable", doc(stmt("Allow", `"*"`,
		`{"StringEquals":{"aws:PrincipalAccount":"${aws:username}"}}`)), true},
	{"IfExists", doc(stmt("Allow", `"*"`,
		`{"StringEqualsIfExists":{"aws:SourceVpc":"vpc-1"}}`)), true},
	{"negated", doc(stmt("Allow", `"*"`,
		`{"StringNotEquals":{"aws:SourceVpc":"vpc-1"}}`)), true},
	{"ForAllValues", doc(stmt("Allow", `"*"`,
		`{"ForAllValues:StringEquals":{"aws:SourceVpce":"vpce-1"}}`)), true},
	{"ForAnyValue", doc(stmt("Allow", `"*"`,
		`{"ForAnyValue:StringEquals":{"aws:SourceVpce":"vpce-1"}}`)), false},
	{"other key", doc(stmt("Allow", `"*"`,
		`{"Bool":{"aws:SecureTransport":"true"}}`)), true},
	{"narrow range", doc(stmt("Allow", `"*"`,
		`{"IpAddress":{"aws:SourceIp":["10.0.0.0/8","192.0.2.1"]}}`)), false},
	{"broad range", doc(stmt("Allow", `"*"`,
		`{"IpAddress":{"aws:SourceIp":"0.0.0.0/1"}}`)), true},
	{"broad mapped range", doc(stmt("Allow", `"*"`,
		`{"IpAddress":{"aws:SourceIp":"::ffff:0.0.0.0/97"}}`)), true},
	{"role sessions by user ID", doc(stmt("Allow", `"*"`,
		`{"StringLike":{"aws:userid":"AROAEXAMPLEROLE00001:*"}}`)), false},
	{"one broad statement of two", doc(
		stmt("Allow", `{"AWS":"`+partnerARN+`"}`, ""), stmt("Allow", `"*"`, "")), true},
}

func TestBroadAccess(t *testing.T) {
	a := New("us-east-1", "000000000000")
	for _, c := range broadCases {
		if err := a.ParseResourcePolicy(c.doc); err != nil {
			t.Fatalf("%s: the case does not parse: %v", c.name, err)
		}
		why, broad, err := BroadAccess([]byte(c.doc))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if broad != c.broad {
			t.Errorf("%s: broad = %v, want %v", c.name, broad, c.broad)
		}
		if broad && why == "" {
			t.Errorf("%s: no reason given", c.name)
		}
	}
}

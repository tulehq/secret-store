package secret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gasmod/gas"
	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/authz"
	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/services/secrets/dirimpl"
	"tule.dev/secret-store/internal/smapi"
)

// storeRotations is contracts.Rotations straight onto the store, starting
// runs that nothing executes: what the module does is under test, not the
// rotation service's runs. unavailable makes it a service without a
// functions endpoint. stopped, when set, records the runs StopRun is asked
// to stop.
type storeRotations struct {
	store       contracts.SecretsProvider
	stopped     *[]string
	unavailable bool
}

func (r storeRotations) Available() bool { return !r.unavailable }

func (r storeRotations) Rotate(
	ctx context.Context,
	in contracts.StartRotationInput,
) (*contracts.RotationStarted, error) {
	in.Now = time.Now()
	return r.store.StartRotation(ctx, in)
}

func (r storeRotations) Cancel(ctx context.Context, id string) (*contracts.SecretVersion, error) {
	out, err := r.store.CancelRotation(ctx, id)
	if err != nil {
		return nil, err
	}
	return &out.SecretVersion, nil
}

func (r storeRotations) StopRun(runID string) {
	if r.stopped != nil {
		*r.stopped = append(*r.stopped, runID)
	}
}

const (
	rotationFn  = "arn:aws:lambda:us-east-1:000000000000:function:rotate"
	rotateToken = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

// rotationModule is a Module over a fresh store holding app/db, with the
// store-backed rotations, signed by dev with the policy docs, or by root
// without any.
func rotationModule(t *testing.T, docs ...string) (*Module, context.Context) {
	t.Helper()
	svc := dirimpl.NewService(&dirimpl.Settings{
		RootDir: t.TempDir(), Region: "us-east-1", AccountID: "000000000000",
	})(&gas.NopLogger{})
	if err := svc.Init(contracts.Unchecked(context.Background())); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(contracts.Unchecked(context.Background())) })
	v := "v1"
	put(t, svc, contracts.CreateSecretInput{Name: "app/db", Payload: contracts.Payload{String: &v}})

	p := rootPrincipal()
	if docs != nil {
		p = sigv4.Principal{
			AccountID: "000000000000", ARN: devARN, PrincipalARN: devARN,
			UserID: "AIDAEXAMPLEDEV00001", Type: sigv4.PrincipalTypeUser,
		}
		for _, d := range docs {
			p.Policies = append(p.Policies, json.RawMessage(d))
		}
	}
	az := authz.New("us-east-1", "000000000000")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r = r.WithContext(sigv4.NewContext(r.Context(), p))
	r, err := az.Attach(r)
	if err != nil {
		t.Fatal(err)
	}
	m := &Module{
		secrets: svc, authz: az, logger: &gas.NopLogger{},
		principals: contracts.UnboundPrincipals{}, rotations: storeRotations{store: svc},
	}
	m.handlers = m.routes()
	return m, r.Context()
}

func allow(actions ...string) string {
	b, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": map[string]any{
		"Effect": "Allow", "Action": actions, "Resource": "*",
	}})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func rotateBody() map[string]any {
	return map[string]any{
		"SecretId": "app/db", "RotationLambdaARN": rotationFn, "ClientRequestToken": rotateToken,
		"RotationRules": map[string]any{"ScheduleExpression": "rate(10 days)", "Duration": "2h"},
	}
}

// errorType returns the error type of a response, or "" for a success.
func errorType(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code == http.StatusOK {
		return ""
	}
	var e smapi.Error
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode %d %s: %v", w.Code, w.Body.String(), err)
	}
	return e.Type
}

func TestRotationAnswers501WithoutAFunctionsEndpoint(t *testing.T) {
	m, ctx := rotationModule(t)
	m.rotations = storeRotations{unavailable: true}
	for _, op := range []string{"RotateSecret", "CancelRotateSecret"} {
		w := call(ctx, m, op, rotateBody())
		if w.Code != http.StatusNotImplemented || errorType(t, w) != smapi.TypeNotImplemented {
			t.Fatalf("%s: %d %s, want 501 NotImplementedException", op, w.Code, w.Body.String())
		}
	}
}

func TestRotateSecretAnswersWithTheNewVersion(t *testing.T) {
	m, ctx := rotationModule(t)
	w := call(ctx, m, "RotateSecret", rotateBody())
	var got smapi.CreateSecretResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", w.Code, w.Body.String())
	}
	if got.VersionID != rotateToken || got.Name != "app/db" ||
		!strings.HasPrefix(got.ARN, ownBase+"app/db-") {
		t.Fatalf("rotate answered %+v", got)
	}
}

// rotateRefusals are RotateSecret requests refused before evaluation, each
// an edit of rotateBody, and the error type each gets.
var rotateRefusals = []struct {
	name string
	edit func(map[string]any)
	want string
}{
	{
		"short token",
		func(b map[string]any) { b["ClientRequestToken"] = "short" },
		smapi.TypeValidation,
	},
	{
		"long token",
		func(b map[string]any) { b["ClientRequestToken"] = strings.Repeat("a", 65) },
		smapi.TypeValidation,
	},
	{
		"long function",
		func(b map[string]any) { b["RotationLambdaARN"] = strings.Repeat("a", 2049) },
		smapi.TypeValidation,
	},
	{"not a function ARN", func(b map[string]any) {
		b["RotationLambdaARN"] = "arn:aws:sqs:us-east-1:000000000000:queue"
	}, smapi.TypeInvalidParameter},
	{"days below 1", func(b map[string]any) {
		b["RotationRules"] = map[string]any{"AutomaticallyAfterDays": 0}
	}, smapi.TypeValidation},
	{"days above 1000", func(b map[string]any) {
		b["RotationRules"] = map[string]any{"AutomaticallyAfterDays": 1001}
	}, smapi.TypeValidation},
	{"duration pattern", func(b map[string]any) {
		b["RotationRules"] = map[string]any{
			"ScheduleExpression": "rate(1 day)",
			"Duration":           "2d",
		}
	}, smapi.TypeValidation},
	{"expression pattern", func(b map[string]any) {
		b["RotationRules"] = map[string]any{"ScheduleExpression": "rate(1 day);"}
	}, smapi.TypeValidation},
	{"both schedules", func(b map[string]any) {
		b["RotationRules"] = map[string]any{
			"AutomaticallyAfterDays": 1, "ScheduleExpression": "rate(1 day)",
		}
	}, smapi.TypeInvalidParameter},
	{"too often", func(b map[string]any) {
		b["RotationRules"] = map[string]any{"ScheduleExpression": "rate(2 hours)"}
	}, smapi.TypeInvalidParameter},
	{"external role", func(b map[string]any) {
		b["ExternalSecretRotationRoleArn"] = "arn:aws:iam::000000000000:role/partner"
	}, smapi.TypeInvalidParameter},
}

func TestRotateSecretRefusesWhatTheModelRefuses(t *testing.T) {
	for _, tt := range rotateRefusals {
		t.Run(tt.name, func(t *testing.T) {
			m, ctx := rotationModule(t)
			body := rotateBody()
			tt.edit(body)
			w := call(ctx, m, "RotateSecret", body)
			if got := errorType(t, w); got != tt.want {
				t.Fatalf("%d %s, want %s", w.Code, w.Body.String(), tt.want)
			}
		})
	}
}

func TestRotateSecretWithoutAFunctionIsAnInvalidRequest(t *testing.T) {
	m, ctx := rotationModule(t)
	body := rotateBody()
	delete(body, "RotationLambdaARN")
	w := call(ctx, m, "RotateSecret", body)
	if errorType(t, w) != smapi.TypeInvalidRequest ||
		!strings.Contains(w.Body.String(), "No Lambda rotation function ARN") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestASecondRotateSecretIsInProgress(t *testing.T) {
	m, ctx := rotationModule(t)
	call(ctx, m, "RotateSecret", rotateBody())
	body := rotateBody()
	body["ClientRequestToken"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	w := call(ctx, m, "RotateSecret", body)
	if errorType(t, w) != smapi.TypeInvalidRequest ||
		!strings.Contains(w.Body.String(), "A previous rotation isn't complete.") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestRotateSecretNeedsInvokeFunctionOnTheFunction(t *testing.T) {
	m, ctx := rotationModule(t, allow("secretsmanager:RotateSecret"))
	w := call(ctx, m, "RotateSecret", rotateBody())
	want := "User: " + devARN + " is not authorized to perform: lambda:InvokeFunction on " +
		"resource: " + rotationFn + " because no identity-based policy allows the " +
		"lambda:InvokeFunction action"
	if errorType(t, w) != smapi.TypeAccessDenied || !strings.Contains(w.Body.String(), want) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}

	m, ctx = rotationModule(t, allow("lambda:InvokeFunction"))
	w = call(ctx, m, "RotateSecret", rotateBody())
	if errorType(t, w) != smapi.TypeAccessDenied ||
		!strings.Contains(w.Body.String(), "secretsmanager:RotateSecret") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}

	m, ctx = rotationModule(t, allow("secretsmanager:RotateSecret", "lambda:InvokeFunction"))
	if w = call(ctx, m, "RotateSecret", rotateBody()); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestInvokeFunctionIsCheckedOnTheStoredFunction(t *testing.T) {
	// The secret has a function; a request naming none is checked on it.
	onOther := `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":"secretsmanager:*","Resource":"*"},` +
		`{"Effect":"Allow","Action":"lambda:InvokeFunction",` +
		`"Resource":"arn:aws:lambda:us-east-1:000000000000:function:other"}]}`
	m, ctx := rotationModule(t, onOther)
	if _, err := m.secrets.StartRotation(contracts.Unchecked(ctx), contracts.StartRotationInput{
		SecretID: "app/db", LambdaARN: rotationFn, TestOnly: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.secrets.CancelRotation(contracts.Unchecked(ctx), "app/db"); err != nil {
		t.Fatal(err)
	}

	w := call(ctx, m, "RotateSecret", map[string]any{"SecretId": "app/db"})
	if errorType(t, w) != smapi.TypeAccessDenied || !strings.Contains(w.Body.String(), rotationFn) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestRotateSecretSuppliesItsConditionKeys(t *testing.T) {
	tests := []struct {
		edit      func(map[string]any)
		name      string
		condition string
	}{
		{
			name:      "RotationLambdaARN",
			condition: `{"ArnEquals":{"secretsmanager:RotationLambdaARN":"` + rotationFn + `"}}`,
		},
		{
			name:      "RotateImmediately",
			condition: `{"Bool":{"secretsmanager:RotateImmediately":"false"}}`,
			edit:      func(b map[string]any) { b["RotateImmediately"] = false },
		},
		{
			name:      "ModifyRotationRules",
			condition: `{"Bool":{"secretsmanager:ModifyRotationRules":"true"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deny := `{"Version":"2012-10-17","Statement":[` +
				`{"Effect":"Allow","Action":["secretsmanager:RotateSecret","lambda:InvokeFunction"],"Resource":"*"},` +
				`{"Effect":"Deny","Action":"secretsmanager:RotateSecret","Resource":"*","Condition":` +
				tt.condition + `}]}`
			m, ctx := rotationModule(t, deny)
			body := rotateBody()
			if tt.edit != nil {
				tt.edit(body)
			}
			w := call(ctx, m, "RotateSecret", body)
			if errorType(t, w) != smapi.TypeAccessDenied {
				t.Fatalf("%d %s, want the Deny on %s to apply", w.Code, w.Body.String(), tt.name)
			}
		})
	}
}

func TestDeleteSecretStopsTheRunItEnds(t *testing.T) {
	m, ctx := rotationModule(t)
	var stopped []string
	m.rotations = storeRotations{store: m.secrets, stopped: &stopped}
	started, err := m.secrets.StartRotation(contracts.Unchecked(ctx), contracts.StartRotationInput{
		SecretID: "app/db", LambdaARN: rotationFn,
	})
	if err != nil {
		t.Fatal(err)
	}

	if w := call(
		ctx,
		m,
		"DeleteSecret",
		map[string]any{"SecretId": "app/db"},
	); w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if len(stopped) != 1 || stopped[0] != started.Run.ID {
		t.Fatalf("stopped %v, want the run %s", stopped, started.Run.ID)
	}
}

func TestTheStoredRotationFunctionIsAResourceKey(t *testing.T) {
	deny := `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"*"},` +
		`{"Effect":"Deny","Action":"secretsmanager:GetSecretValue","Resource":"*","Condition":` +
		`{"ArnEquals":{"secretsmanager:resource/AllowRotationLambdaArn":"` + rotationFn + `"}}}]}`
	m, ctx := rotationModule(t, deny)
	read := map[string]any{"SecretId": "app/db"}
	if w := call(ctx, m, "GetSecretValue", read); w.Code != http.StatusOK {
		t.Fatalf("before rotation is configured: %d %s", w.Code, w.Body.String())
	}

	if _, err := m.secrets.StartRotation(contracts.Unchecked(ctx), contracts.StartRotationInput{
		SecretID: "app/db", LambdaARN: rotationFn,
	}); err != nil {
		t.Fatal(err)
	}
	if w := call(ctx, m, "GetSecretValue", read); errorType(t, w) != smapi.TypeAccessDenied {
		t.Fatalf("with the function stored: %d %s, want the Deny to apply", w.Code, w.Body.String())
	}
}

func TestCancelRotateSecretIsEvaluated(t *testing.T) {
	m, ctx := rotationModule(t, allow("secretsmanager:RotateSecret"))
	w := call(ctx, m, "CancelRotateSecret", map[string]any{"SecretId": "app/db"})
	if errorType(t, w) != smapi.TypeAccessDenied ||
		!strings.Contains(w.Body.String(), "secretsmanager:CancelRotateSecret") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

// rotationFields is the rotation members of a DescribeSecret or ListSecrets
// entry, as raw JSON so an absent member can be told from a null one.
type rotationFields map[string]json.RawMessage

// describeFields returns app/db's members as DescribeSecret and ListSecrets
// answer them.
func describeFields(ctx context.Context, t *testing.T, m *Module) []rotationFields {
	t.Helper()
	var d rotationFields
	w := call(ctx, m, "DescribeSecret", map[string]any{"SecretId": "app/db"})
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatalf("describe: %d %s", w.Code, w.Body.String())
	}
	var l struct{ SecretList []rotationFields }
	w = call(ctx, m, "ListSecrets", map[string]any{})
	if err := json.Unmarshal(w.Body.Bytes(), &l); err != nil || len(l.SecretList) != 1 {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	return []rotationFields{d, l.SecretList[0]}
}

// requireFields fails unless every entry has the members of want, as want
// gives them, or "" for present with any value, and none of absent.
func requireFields(
	t *testing.T,
	entries []rotationFields,
	want map[string]string,
	absent ...string,
) {
	t.Helper()
	for i, f := range entries {
		for k, v := range want {
			got, ok := f[k]
			if !ok || (v != "" && string(got) != v) {
				t.Fatalf("entry %d: %s = %s, want %s", i, k, got, v)
			}
		}
		for _, k := range absent {
			if _, ok := f[k]; ok {
				t.Fatalf("entry %d reports %s", i, k)
			}
		}
	}
}

func TestDescribeAndListReportRotation(t *testing.T) {
	m, ctx := rotationModule(t)

	// Never configured: none of the members.
	requireFields(t, describeFields(ctx, t, m), nil, "RotationEnabled", "RotationLambdaARN",
		"RotationRules", "LastRotatedDate", "NextRotationDate")

	call(ctx, m, "RotateSecret", rotateBody())
	requireFields(t, describeFields(ctx, t, m), map[string]string{
		"RotationEnabled":   "true",
		"RotationLambdaARN": `"` + rotationFn + `"`,
		"RotationRules":     `{"Duration":"2h","ScheduleExpression":"rate(10 days)"}`,
		"NextRotationDate":  "",
	}, "LastRotatedDate")

	// Turned off: the configuration stays, the dates go.
	call(ctx, m, "CancelRotateSecret", map[string]any{"SecretId": "app/db"})
	requireFields(t, describeFields(ctx, t, m), map[string]string{
		"RotationEnabled":   "false",
		"RotationLambdaARN": `"` + rotationFn + `"`,
		"RotationRules":     `{"Duration":"2h","ScheduleExpression":"rate(10 days)"}`,
	}, "LastRotatedDate", "NextRotationDate")
}

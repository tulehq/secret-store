package secret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/gasmod/gas"
	"tule.dev/identity/principals"
	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/authz"
	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/services/secrets/dirimpl"
	"tule.dev/secret-store/internal/smapi"
)

const (
	// devID is the unique ID the fake binds devARN to.
	devID = "AIDAEXAMPLEDEV00001"
	// goneARN is a user ARN no user has.
	goneARN = "arn:aws:iam::000000000000:user/gone"
)

func grantTo(arn string) string {
	return `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
		`"Principal":{"AWS":"` + arn + `"},"Action":"secretsmanager:GetSecretValue",` +
		`"Resource":"*"}}`
}

// fakePrincipals binds devARN to devID and shows devID as devARN, refuses
// goneARN, and records what it returned. fail makes every call fail.
type fakePrincipals struct {
	fail error
	// id, when set, is what devARN is bound to in place of devID.
	id    string
	bound []string
	binds int
	shows int
	mu    sync.Mutex
}

func (f *fakePrincipals) Bind(_ context.Context, doc string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.binds++
	if f.fail != nil {
		return "", f.fail
	}
	if strings.Contains(doc, goneARN) {
		return "", &principals.InvalidPrincipalError{ARN: goneARN}
	}
	id := devID
	if f.id != "" {
		id = f.id
	}
	out := strings.ReplaceAll(doc, devARN, id)
	f.bound = append(f.bound, out)
	return out, nil
}

func (f *fakePrincipals) Show(_ context.Context, doc string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shows++
	if f.fail != nil {
		return "", f.fail
	}
	return strings.ReplaceAll(doc, devID, devARN), nil
}

// recordingStore is the real store, recording every policy it is given to
// store.
type recordingStore struct {
	*dirimpl.Service
	stored []string
	mu     sync.Mutex
}

func (s *recordingStore) PutResourcePolicy(
	ctx context.Context,
	secretID, doc string,
) (*contracts.SecretRef, error) {
	s.mu.Lock()
	s.stored = append(s.stored, doc)
	s.mu.Unlock()
	return s.Service.PutResourcePolicy(ctx, secretID, doc)
}

// boundModule is a Module over a fresh store holding app/db with a policy
// bound to devID, signed by p.
func boundModule(
	t *testing.T,
	p sigv4.Principal,
) (*Module, *recordingStore, *fakePrincipals, context.Context) {
	t.Helper()
	svc := dirimpl.NewService(&dirimpl.Settings{
		RootDir: t.TempDir(), Region: "us-east-1", AccountID: "000000000000",
	})(&gas.NopLogger{})
	if err := svc.Init(contracts.Unchecked(context.Background())); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(contracts.Unchecked(context.Background())) })
	put(t, svc, contracts.CreateSecretInput{Name: "app/db"})
	if _, err := svc.PutResourcePolicy(contracts.Unchecked(context.Background()),
		"app/db", grantTo(devID)); err != nil {
		t.Fatal(err)
	}

	az := authz.New("us-east-1", "000000000000")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r = r.WithContext(sigv4.NewContext(r.Context(), p))
	r, err := az.Attach(r)
	if err != nil {
		t.Fatal(err)
	}
	store := &recordingStore{Service: svc}
	fake := &fakePrincipals{}
	m := &Module{secrets: store, authz: az, principals: fake, logger: &gas.NopLogger{}}
	m.handlers = m.routes()
	return m, store, fake, r.Context()
}

func rootPrincipal() sigv4.Principal {
	return sigv4.Principal{
		AccountID: "000000000000", ARN: "arn:aws:iam::000000000000:root",
		PrincipalARN: "arn:aws:iam::000000000000:root", UserID: "000000000000",
		Type: sigv4.PrincipalTypeAccount, Root: true,
	}
}

// call dispatches op with body as ctx's principal and returns the response.
func call(ctx context.Context, m *Module, op string, body any) *httptest.ResponseRecorder {
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/", strings.NewReader(string(raw)))
	r.Header.Set(smapi.TargetHeader, "secretsmanager."+op)
	w := httptest.NewRecorder()
	_ = m.dispatch(gas.NewContext(ctx, w, r))
	return w
}

// everyMember is one body carrying every member any operation reads, so
// that each routed operation, sent it, does what it can with app/db and a
// policy naming devARN.
func everyMember() map[string]any {
	return map[string]any{
		"SecretId":       "app/db",
		"SecretIdList":   []string{"app/db"},
		"Name":           "app/other",
		"SecretString":   "value",
		"ResourcePolicy": grantTo(devARN),
		"Tags":           []map[string]string{{"Key": "team", "Value": "core"}},
		"TagKeys":        []string{"team"},
		"VersionStage":   "AWSPENDING",
		"VersionStages":  []string{"AWSPENDING"},
		"Description":    "described",
	}
}

// TestEveryPathBindsWhatItStoresAndShowsWhatItReturns sends every routed
// operation against a secret whose stored policy is bound: no response may
// carry the stored unique ID, which only Show turns back into the ARN, and
// every policy the store is given must be one Bind returned. An operation
// that stores or returns a policy without them fails here.
func TestEveryPathBindsWhatItStoresAndShowsWhatItReturns(t *testing.T) {
	for op := range (&Module{}).routes() {
		t.Run(op, func(t *testing.T) {
			m, store, fake, ctx := boundModule(t, rootPrincipal())
			w := call(ctx, m, op, everyMember())
			if strings.Contains(w.Body.String(), devID) {
				t.Errorf("the response carries the stored unique ID: %s", w.Body.String())
			}
			for _, doc := range store.stored {
				if !slices.Contains(fake.bound, doc) {
					t.Errorf("stored a policy Bind did not return: %s", doc)
				}
			}
		})
	}
}

func TestPutStoresTheBoundPolicyAndGetShowsIt(t *testing.T) {
	m, store, fake, ctx := boundModule(t, rootPrincipal())
	if w := call(ctx, m, "PutResourcePolicy", everyMember()); w.Code != http.StatusOK {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	if len(store.stored) != 1 || store.stored[0] != grantTo(devID) {
		t.Fatalf("stored %q", store.stored)
	}
	w := call(ctx, m, "GetResourcePolicy", map[string]string{"SecretId": "app/db"})
	var got smapi.ResourcePolicyResponse
	if err := json.Unmarshal(
		w.Body.Bytes(),
		&got,
	); err != nil ||
		got.ResourcePolicy != grantTo(devARN) {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
	if fake.binds != 1 || fake.shows != 1 {
		t.Fatalf("binds %d, shows %d", fake.binds, fake.shows)
	}
}

func TestAPutNamingNoOneIsMalformed(t *testing.T) {
	m, store, _, ctx := boundModule(t, rootPrincipal())
	body := everyMember()
	body["ResourcePolicy"] = grantTo(goneARN)
	w := call(ctx, m, "PutResourcePolicy", body)
	if w.Code != http.StatusBadRequest ||
		w.Header().Get("X-Amzn-Errortype") != smapi.TypeMalformedPolicy ||
		!strings.Contains(w.Body.String(), invalidPrincipal) {
		t.Fatalf("got %d %s %s", w.Code, w.Header(), w.Body.String())
	}
	if len(store.stored) != 0 {
		t.Fatalf("stored %q", store.stored)
	}
}

// TestValidateDoesNotLookUpPrincipals checks ValidateResourcePolicy never
// asks identity, with or without a SecretId: a policy naming no one passes,
// and identity being down does not matter. Without a SecretId it is
// evaluated in the caller's own account, so a lookup would tell a caller of
// any account which principals exist.
func TestValidateDoesNotLookUpPrincipals(t *testing.T) {
	for _, withSecret := range []bool{false, true} {
		m, _, fake, ctx := boundModule(t, rootPrincipal())
		fake.fail = errors.New("identity is down")
		body := map[string]any{"ResourcePolicy": grantTo(goneARN)}
		if withSecret {
			body["SecretId"] = "app/db"
		}
		w := call(ctx, m, "ValidateResourcePolicy", body)
		var got smapi.ValidateResourcePolicyResponse
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil ||
			!got.PolicyValidationPassed {
			t.Fatalf("with secret %t: %d %s", withSecret, w.Code, w.Body.String())
		}
		if fake.binds != 0 || fake.shows != 0 {
			t.Fatalf("with secret %t: binds %d, shows %d", withSecret, fake.binds, fake.shows)
		}
	}
}

func TestFailingToReachIdentityFailsTheCall(t *testing.T) {
	for _, op := range []string{"PutResourcePolicy", "GetResourcePolicy"} {
		t.Run(op, func(t *testing.T) {
			m, store, fake, ctx := boundModule(t, rootPrincipal())
			fake.fail = errors.New("identity is down")
			w := call(ctx, m, op, everyMember())
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("got %d %s", w.Code, w.Body.String())
			}
			if len(store.stored) != 0 {
				t.Fatalf("stored %q", store.stored)
			}
		})
	}
}

// TestADeniedCallerLearnsNothingOfPrincipals checks the policy's principals
// are looked up only for a caller allowed the operation: a denied one gets
// AccessDenied whether or not they exist, and identity is not asked.
func TestADeniedCallerLearnsNothingOfPrincipals(t *testing.T) {
	dev := sigv4.Principal{
		AccountID: "000000000000", ARN: devARN, PrincipalARN: devARN,
		UserID: devID, Type: sigv4.PrincipalTypeUser,
	}
	m, _, fake, ctx := boundModule(t, dev)
	body := everyMember()
	body["ResourcePolicy"] = grantTo(goneARN)
	w := call(ctx, m, "PutResourcePolicy", body)
	if w.Header().Get("X-Amzn-Errortype") != smapi.TypeAccessDenied {
		t.Fatalf("got %d %s", w.Code, w.Body.String())
	}
	if fake.binds != 0 {
		t.Fatalf("Bind was called %d times", fake.binds)
	}
}

// TestABoundPolicyIsHeldToTheLengthLimit checks the bound document, not only
// the one sent, is at most maxPolicyLen characters: a unique ID, up to 128
// characters, can be longer than the ARN it replaces.
func TestABoundPolicyIsHeldToTheLengthLimit(t *testing.T) {
	longID := "AIDA" + strings.Repeat("X", 124)
	padded := func(n int) string {
		return `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
			`"Principal":{"AWS":"` + devARN + `"},"Action":"secretsmanager:GetSecretValue",` +
			`"Resource":"*","Condition":{"StringEquals":{"aws:SourceVpce":"` +
			strings.Repeat("v", n) + `"}}}}`
	}
	// The longest document whose binding still fits, and one more.
	grow := len(longID) - len(devARN)
	fits := padded(maxPolicyLen - grow - len(padded(0)))
	over := padded(maxPolicyLen - grow - len(padded(0)) + 1)
	if len(fits) > maxPolicyLen || len(over) > maxPolicyLen {
		t.Fatal("the documents sent must fit themselves")
	}

	m, store, fake, ctx := boundModule(t, rootPrincipal())
	fake.id = longID
	body := everyMember()
	body["ResourcePolicy"] = over
	w := call(ctx, m, "PutResourcePolicy", body)
	if w.Code != http.StatusBadRequest ||
		w.Header().Get("X-Amzn-Errortype") != smapi.TypeValidation {
		t.Fatalf("over: got %d %s", w.Code, w.Body.String())
	}
	if len(store.stored) != 0 {
		t.Fatalf("stored %d policies", len(store.stored))
	}

	body["ResourcePolicy"] = fits
	if w = call(ctx, m, "PutResourcePolicy", body); w.Code != http.StatusOK {
		t.Fatalf("fits: got %d %s", w.Code, w.Body.String())
	}
	if len(store.stored) != 1 || len(store.stored[0]) != maxPolicyLen {
		t.Fatalf("stored %d policies, want one of %d characters", len(store.stored),
			maxPolicyLen)
	}
}

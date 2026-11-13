// Package authz evaluates requests against the IAM policies of the principal
// that signed them and the resource-based policy of the secret they act on,
// with tule.dev/policy, as Secrets Manager does.
//
// The root principal of the store's account, the service's own static key or
// identity's root key, is never evaluated, as AWS never evaluates an
// account's root user against identity policies. Without an identity
// endpoint every request is signed by the static key, so nothing is ever
// evaluated. Every other principal is evaluated on every request, and a
// request the policies do not allow is refused with AccessDeniedException.
//
// The store's secrets belong to its account. A principal of another account
// is evaluated as AWS evaluates a cross-account request: it needs both an
// identity-based Allow and an Allow in the secret's resource-based policy.
package authz

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"tule.dev/policy"
	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/smapi"
)

// Authorizer evaluates requests. It is safe for concurrent use.
type Authorizer struct {
	identity *docCache
	resource *docCache
	region   string
	account  string
}

// New returns an Authorizer for the secrets of region and account, the ones
// the store mints ARNs in.
func New(region, account string) *Authorizer {
	return &Authorizer{
		identity: newDocCache(maxCachedDocs, policy.ParseIdentity),
		resource: newDocCache(maxCachedDocs, policy.ParseResource),
		region:   region,
		account:  account,
	}
}

// subject is who a request is evaluated as: its principal, the principal's
// parsed policies and the global condition keys of the request.
type subject struct {
	global   map[string][]string
	caller   policy.Caller
	policies []*policy.Policy
	root     bool
}

type subjectKey struct{}

// errNoSubject is an internal failure: a request reached a check without
// Attach having run, which only a wiring mistake can cause.
var errNoSubject = errors.New("authz: the request carries no principal to evaluate")

// Attach returns r with what its checks are evaluated against: the principal
// sigv4.Verify put in its context, with that principal's policies parsed.
// It fails, as an internal error, when r carries no verified principal or a
// policy identity supplied does not parse; a request is never served
// without its policies.
func (a *Authorizer) Attach(r *http.Request) (*http.Request, error) {
	p, ok := sigv4.PrincipalFrom(r.Context())
	if !ok {
		return nil, errNoSubject
	}
	if err := rootInStep(p); err != nil {
		return nil, err
	}
	// Root is the root of this store's account only: a root principal of any
	// other account is evaluated, and refused, like any principal of
	// another account.
	root := p.Root && p.AccountID == a.account
	s := &subject{root: root, caller: callerOf(p)}
	if !root {
		policies, err := a.identity.all(p.Policies)
		if err != nil {
			return nil, fmt.Errorf("authz: the policies of %s: %w", p.ARN, err)
		}
		s.policies = policies
		s.global = globalKeys(r, p, a.region)
	}
	return r.WithContext(context.WithValue(r.Context(), subjectKey{}, s)), nil
}

// rootInStep fails, as an internal fault, when p's Root and Type disagree.
// The service skips evaluation from Root, while policy.Authorize grants an
// account root full identity-based access from Type, so the two must say the
// same: an Account principal that is not Root, or a Root principal of another
// Type (none included), is refused rather than evaluated under either
// reading. The service's static key is its account's root user, which
// sigv4.NewStaticKey gives Type Account.
func rootInStep(p sigv4.Principal) error {
	switch {
	case p.Type == sigv4.PrincipalTypeAccount && !p.Root:
		return fmt.Errorf("authz: %s is an account principal that is not root", p.ARN)
	case p.Root && p.Type != sigv4.PrincipalTypeAccount:
		return fmt.Errorf("authz: %s is root with principal type %q", p.ARN, p.Type)
	default:
		return nil
	}
}

// callerOf is the policy.Caller of p, from the fields identity's key source
// fills. tule.dev/policy supplies aws:PrincipalArn, aws:PrincipalAccount,
// aws:userid, aws:PrincipalType and aws:username from it, and refuses a
// caller whose fields disagree, or a session whose role was deleted (an
// empty PrincipalARN), before reading any policy.
func callerOf(p sigv4.Principal) policy.Caller {
	return policy.Caller{
		AccountID:    p.AccountID,
		ARN:          p.ARN,
		PrincipalARN: p.PrincipalARN,
		UserID:       p.UserID,
		Type:         policy.PrincipalType(p.Type),
	}
}

// IsRoot reports whether ctx's request is the root principal's, which every
// check allows. A caller can skip the work of building a check for it. A
// request Attach has not seen is not root.
func IsRoot(ctx context.Context) bool {
	s, ok := ctx.Value(subjectKey{}).(*subject)
	return ok && s.root
}

// ForeignAccount returns the account of ctx's principal when it is not the
// store's, and false for a principal of the store's account or a request
// Attach has not seen.
func (a *Authorizer) ForeignAccount(ctx context.Context) (string, bool) {
	s, ok := ctx.Value(subjectKey{}).(*subject)
	if !ok || s.caller.AccountID == a.account {
		return "", false
	}
	return s.caller.AccountID, true
}

// Request is one check of a request.
type Request struct {
	// Keys are the service condition keys for the check, each of which must
	// be one the operation's Check lists.
	Keys map[string][]string
	// Operation is the routed operation, which selects the Operations entry.
	Operation string
	// Action is the action checked, one of the operation's Checks.
	Action string
	// Resource is the ARN evaluated, or "*".
	Resource string
	// Shown is the resource the AccessDenied message names: the SecretId or
	// Name as the request gave it, as Secrets Manager's messages show it, or
	// "*".
	Shown string
	// Policy is the resource-based policy stored for the secret evaluated,
	// read under the same lock as the secret, or "" when it has none or the
	// check is on no secret.
	Policy string
	// CallersAccount evaluates the check as on a resource of the caller's
	// own account rather than the store's: for an action on "*" that reads
	// nothing of the store's by itself, such as BatchGetSecretValue's own
	// action, whose secrets are each checked with their own policy.
	CallersAccount bool
}

// Check evaluates req for ctx's request, with the principal's identity
// policies and req.Policy, the secret's resource policy, together
// (policy.Authorize), the secret owned by the store's account. It returns
// nil when the request is allowed, an AccessDeniedException *smapi.Error
// when it is denied, and an InvalidParameterException one when the request
// carries more condition context than is evaluated (see capContext). Any
// other error is an internal failure, never an allow; a stored resource
// policy that does not parse is one, so it denies rather than be skipped.
func (a *Authorizer) Check(ctx context.Context, req Request) error {
	s, ok := ctx.Value(subjectKey{}).(*subject)
	if !ok {
		return errNoSubject
	}
	if s.root {
		return nil
	}
	check, err := lookup(req.Operation, req.Action)
	if err != nil {
		return err
	}
	if err = declared(check, req.Keys); err != nil {
		return err
	}

	keys := make(map[string][]string, len(s.global)+len(req.Keys))
	for k, v := range s.global {
		keys[k] = v
	}
	for k, v := range req.Keys {
		keys[k] = v
	}
	if err = capContext(keys); err != nil {
		return err
	}

	resource, err := a.resourcePolicy(req)
	if err != nil {
		return err
	}
	owner := a.account
	if req.CallersAccount {
		owner = s.caller.AccountID
	}
	az := policy.Authorize(policy.AuthorizeRequest{
		Action:          req.Action,
		Resource:        req.Resource,
		ResourceAccount: owner,
		Caller:          s.caller,
		Context:         keys,
	}, resource, s.policies...)
	return decide(az, s.caller.ARN, req)
}

// resourcePolicy returns req.Policy parsed, or nil when it is empty. A
// stored policy that does not parse is an internal error, so the check
// denies rather than skip it.
func (a *Authorizer) resourcePolicy(req Request) (*policy.Policy, error) {
	if req.Policy == "" {
		return nil, nil //nolint:nilnil // no policy is not an error
	}
	p, err := a.resource.get([]byte(req.Policy))
	if err != nil {
		return nil, fmt.Errorf("authz: the resource policy stored for %s: %w", req.Resource, err)
	}
	return p, nil
}

// decide turns az, the decision for req made for the principal arn, into
// Check's answer, with AWS's AccessDenied message: "User: <arn> is not
// authorized to perform: <action> on resource: <resource> " and the reason,
// as policy.Reason words it ("with an explicit deny in an identity-based
// policy", "with an explicit deny in a resource-based policy", "because no
// identity-based policy allows the <action> action", "because no
// resource-based policy allows the <action> action"; IAM User Guide,
// troubleshoot_access-denied.html).
func decide(az policy.Authorization, arn string, req Request) error {
	if az.Decision == policy.Allow {
		return nil
	}
	if az.Reason == policy.NoReason {
		return fmt.Errorf("authz: %s on %s was denied without a reason", req.Action, req.Resource)
	}
	return smapi.ErrAccessDenied(fmt.Sprintf(
		"User: %s is not authorized to perform: %s on resource: %s %s",
		arn, req.Action, req.Shown, az.Reason.Message(req.Action)))
}

// lookup returns the Check of op for action. A pair the mapping does not
// list is a wiring mistake, failed rather than evaluated.
func lookup(op, action string) (Check, error) {
	for _, c := range Operations[op] {
		if c.Action == action {
			return c, nil
		}
	}
	return Check{}, fmt.Errorf("authz: the mapping has no check of %s for %s", action, op)
}

// declared fails unless every key is one check lists, so the mapping says
// exactly what is supplied.
func declared(check Check, keys map[string][]string) error {
	for k := range keys {
		if !listed(check.Keys, k) {
			return fmt.Errorf("authz: the mapping lists no key %s for %s", k, check.Action)
		}
	}
	return nil
}

// tagPlaceholders are the reference's spellings of a key with a tag key in it.
var tagPlaceholders = []string{"${TagKey}", "tag-key"}

func listed(names []string, key string) bool {
	for _, n := range names {
		if n == key {
			return true
		}
		for _, ph := range tagPlaceholders {
			if prefix, ok := strings.CutSuffix(n, ph); ok && strings.HasPrefix(key, prefix) &&
				len(key) > len(prefix) {
				return true
			}
		}
	}
	return false
}

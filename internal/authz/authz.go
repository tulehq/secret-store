// Package authz evaluates requests against the identity-based IAM policies
// of the principal that signed them, with tule.dev/policy, as Secrets
// Manager does.
//
// The root principal of the store's account, the service's own static key or
// identity's root key, is never evaluated, as AWS never evaluates an account's root user against
// identity policies. Without an identity endpoint every request is signed by
// the static key, so nothing is ever evaluated. Every other principal is
// evaluated on every request, and a request no policy allows is refused with
// AccessDeniedException.
//
// A principal of another account than the store's is refused every request.
// On AWS a cross-account request needs a resource-based policy granting it as
// well as the caller's identity policy, and resource policies are not
// evaluated here, so nothing can grant one; and since every account shares
// this store's secrets, allowing it would let another account reach them.
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
	cache   *docCache
	region  string
	account string
}

// New returns an Authorizer for the secrets of region and account, the ones
// the store mints ARNs in.
func New(region, account string) *Authorizer {
	return &Authorizer{cache: newDocCache(maxCachedDocs), region: region, account: account}
}

// subject is who a request is evaluated as: its principal, the principal's
// parsed policies and the global condition keys of the request.
type subject struct {
	global   map[string][]string
	arn      string
	account  string
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
	// Root is the root of this store's account only: a root principal of any
	// other account is evaluated, and refused, like any principal of
	// another account.
	root := p.Root && p.AccountID == a.account
	s := &subject{root: root, arn: p.ARN, account: p.AccountID}
	if !root {
		policies, err := a.cache.parse(p.Policies)
		if err != nil {
			return nil, fmt.Errorf("authz: the policies of %s: %w", p.ARN, err)
		}
		s.policies = policies
		s.global = globalKeys(r, p, a.region)
	}
	return r.WithContext(context.WithValue(r.Context(), subjectKey{}, s)), nil
}

// IsRoot reports whether ctx's request is the root principal's, which every
// check allows. A caller can skip the work of building a check for it. A
// request Attach has not seen is not root.
func IsRoot(ctx context.Context) bool {
	s, ok := ctx.Value(subjectKey{}).(*subject)
	return ok && s.root
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
}

// Check evaluates req for ctx's request. It returns nil when the request is
// allowed, an AccessDeniedException *smapi.Error when it is denied, and an
// InvalidParameterException one when the request carries more condition
// context than is evaluated (see capContext). Any other error is an
// internal failure, never an allow.
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

	res := policy.Evaluate(policy.Request{
		Action:    req.Action,
		Resource:  req.Resource,
		Principal: s.arn,
		Context:   keys,
	}, s.policies...)
	return decide(res.Decision, s.account != a.account, s.arn, req)
}

// decide turns the identity-policy decision for req, made for the principal
// arn, into Check's answer, with AWS's AccessDenied messages. A principal of
// another account that its identity policies allow is still denied, as
// AWS denies a cross-account request no resource-based policy allows.
func decide(d policy.Decision, crossAccount bool, arn string, req Request) error {
	switch {
	case d == policy.Allow && !crossAccount:
		return nil
	case d == policy.Allow:
		return smapi.ErrAccessDenied(fmt.Sprintf(
			"User: %s is not authorized to perform: %s on resource: %s "+
				"because no resource-based policy allows the %s action",
			arn, req.Action, req.Shown, req.Action))
	case d == policy.ExplicitDeny:
		return smapi.ErrAccessDenied(fmt.Sprintf(
			"User: %s is not authorized to perform: %s on resource: %s "+
				"with an explicit deny in an identity-based policy",
			arn, req.Action, req.Shown))
	default:
		return smapi.ErrAccessDenied(fmt.Sprintf(
			"User: %s is not authorized to perform: %s on resource: %s "+
				"because no identity-based policy allows the %s action",
			arn, req.Action, req.Shown, req.Action))
	}
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

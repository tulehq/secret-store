package contracts

import "context"

// PolicyPrincipals binds the principals of a resource policy to unique IDs
// when it is saved, and shows a bound policy as AWS shows it, as identity's
// principals client does (tule.dev/identity/principals).
//
// AWS turns a user or role ARN in a resource policy's Principal into the
// principal's unique ID when the policy is saved, so a user or role deleted
// and created again under the same ARN is another principal, which the
// policy does not name (IAM User Guide, AWS JSON policy elements: Principal).
// A policy is evaluated as stored, bound.
type PolicyPrincipals interface {
	// Bind returns doc, a resource policy that parsed, with each user and
	// role ARN in its principals replaced by the unique ID of the IAM user or
	// role that has it now. An ARN no user or role has is an error matching
	// principals.ErrInvalidPrincipal; any other error is a failure to ask.
	Bind(ctx context.Context, doc string) (string, error)
	// Show returns doc, a stored policy, with each unique ID a user or role
	// still has turned back into its current ARN, and the others left as
	// they are.
	Show(ctx context.Context, doc string) (string, error)
}

// UnboundPrincipals is PolicyPrincipals for a store run without identity,
// which has no unique IDs to bind to: a policy is stored and shown as it was
// sent, and its principals are matched by ARN.
type UnboundPrincipals struct{}

// Bind returns doc unchanged.
func (UnboundPrincipals) Bind(_ context.Context, doc string) (string, error) {
	return doc, nil
}

// Show returns doc unchanged.
func (UnboundPrincipals) Show(_ context.Context, doc string) (string, error) {
	return doc, nil
}

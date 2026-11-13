package secret

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/gasmod/gas"
	"tule.dev/identity/principals"

	"tule.dev/secret-store/internal/authz"
	"tule.dev/secret-store/internal/smapi"
)

// The resource-policy operations, as the Secrets Manager API reference gives
// them (PutResourcePolicy, GetResourcePolicy, DeleteResourcePolicy,
// ValidateResourcePolicy).
const (
	// maxPolicyLen is ResourcePolicy's "Maximum length of 20480", the
	// "Resource-based policy length" quota: "The maximum number of
	// characters in a resource-based permissions policy attached to a
	// secret." It counts characters, not bytes.
	maxPolicyLen = 20480
	// defaultPolicyName is the one policy a secret has: "If you don't
	// specify this field, Secrets Manager uses default. You can only attach
	// the default policy".
	defaultPolicyName = "default"
	// maxPolicyNameLen and policyNamePattern are PolicyName's constraints.
	maxPolicyNameLen  = 64
	policyNamePattern = `[0-9A-Za-z\-\_]+`
	// broadAccessCheck names ValidateResourcePolicy's broad-access check in
	// ValidationErrors. AWS does not document its check names; this one is
	// the service's own.
	broadAccessCheck = "BROAD_ACCESS"
)

func (m *Module) putResourcePolicy(ctx gas.Context) error {
	req, err := decode[smapi.PutResourcePolicyRequest](ctx)
	if err != nil {
		return err
	}
	if err = requireSecretID(req.SecretID); err != nil {
		return err
	}
	if err = checkPolicyName(req.PolicyName, false); err != nil {
		return err
	}
	doc, err := m.requirePolicy(req.ResourcePolicy)
	if err != nil {
		return err
	}
	if req.BlockPublicPolicy != nil && *req.BlockPublicPolicy {
		if err = blockPublic(doc); err != nil {
			return err
		}
	}

	sctx := m.guardSecret(ctx, "PutResourcePolicy", req.SecretID, putKeys(req))
	bound, err := m.bindFor(ctx, sctx, req.SecretID, doc)
	if err != nil {
		return err
	}
	out, err := m.secrets.PutResourcePolicy(sctx, req.SecretID, bound)
	if err != nil {
		return err
	}
	return smapi.Write(ctx, smapi.ResourcePolicyResponse{
		SecretRefResponse: secretRef(*out),
		PolicyName:        defaultPolicyName,
	})
}

// bindFor returns doc bound (bindPolicy) for PutResourcePolicy on secretID,
// once sctx's check allows it. The check runs first, on its own, so that
// only a caller allowed to attach the policy learns whether the principals
// it names exist, and identity is not asked while the store is locked. The
// store runs the check again under its lock when it stores the policy, on
// the secret it acts on.
func (m *Module) bindFor(ctx, sctx context.Context, secretID, doc string) (string, error) {
	if _, err := m.secrets.GetResourcePolicy(sctx, secretID); err != nil {
		return "", err
	}
	return m.bindPolicy(ctx, doc)
}

// putKeys returns PutResourcePolicy's own keys: secretsmanager:PolicyName
// and secretsmanager:BlockPublicPolicy, each when the request gives it.
func putKeys(req smapi.PutResourcePolicyRequest) map[string][]string {
	keys := optional(nil, "secretsmanager:PolicyName", deref(req.PolicyName))
	if req.BlockPublicPolicy != nil {
		keys = optional(keys, "secretsmanager:BlockPublicPolicy",
			strconv.FormatBool(*req.BlockPublicPolicy))
	}
	return keys
}

// blockPublic refuses doc with PublicPolicyException when it grants broad
// access. AWS does not document the exception's message; this one is the
// service's own.
func blockPublic(doc string) error {
	why, broad, err := broadAccess(doc)
	if err != nil {
		return err
	}
	if broad {
		return smapi.ErrPublicPolicy("BlockPublicPolicy is set and the resource policy " +
			"grants broad access to the secret. " + why)
	}
	return nil
}

func (m *Module) getResourcePolicy(ctx gas.Context) error {
	req, err := decode[smapi.ResourcePolicyRequest](ctx)
	if err != nil {
		return err
	}
	if err = requireSecretID(req.SecretID); err != nil {
		return err
	}
	if err = checkPolicyName(req.PolicyName, true); err != nil {
		return err
	}
	keys := optional(nil, "secretsmanager:PolicyName", deref(req.PolicyName))
	sctx := m.guardSecret(ctx, "GetResourcePolicy", req.SecretID, keys)
	out, err := m.secrets.GetResourcePolicy(sctx, req.SecretID)
	if err != nil {
		return err
	}
	res := smapi.ResourcePolicyResponse{SecretRefResponse: secretRef(out.SecretRef)}
	if out.Policy != "" {
		shown, err := m.principals.Show(ctx, out.Policy)
		if err != nil {
			return fmt.Errorf("show the resource policy of %s: %w", out.Name, err)
		}
		res.PolicyName = defaultPolicyName
		res.ResourcePolicy = shown
	}
	return smapi.Write(ctx, res)
}

func (m *Module) deleteResourcePolicy(ctx gas.Context) error {
	req, err := decode[smapi.ResourcePolicyRequest](ctx)
	if err != nil {
		return err
	}
	if err = requireSecretID(req.SecretID); err != nil {
		return err
	}
	if err = checkPolicyName(req.PolicyName, false); err != nil {
		return err
	}
	keys := optional(nil, "secretsmanager:PolicyName", deref(req.PolicyName))
	sctx := m.guardSecret(ctx, "DeleteResourcePolicy", req.SecretID, keys)
	out, err := m.secrets.DeleteResourcePolicy(sctx, req.SecretID)
	if err != nil {
		return err
	}
	return smapi.Write(ctx, smapi.ResourcePolicyResponse{
		SecretRefResponse: secretRef(*out),
		PolicyName:        defaultPolicyName,
	})
}

// validateResourcePolicy checks a policy without storing it: its syntax,
// answered MalformedPolicyDocumentException as PutResourcePolicy answers it,
// and broad access, answered in ValidationErrors. It does not check that the
// users and roles the policy names exist, which AWS documents no check for:
// without a SecretId it is evaluated in the caller's own account, so it
// would let a caller of any account learn which principals exist. Only
// PutResourcePolicy, which needs a grant on a secret, binds them. Secrets Manager also
// "Verifies the policy does not lock out a caller", a check this service
// does not make. With a SecretId the secret must exist and not be scheduled
// for deletion, and the caller is checked on it, with its stored policy;
// without one, on "*".
func (m *Module) validateResourcePolicy(ctx gas.Context) error {
	req, err := decode[smapi.ValidateResourcePolicyRequest](ctx)
	if err != nil {
		return err
	}
	if err = optionalSecretID(req.SecretID); err != nil {
		return err
	}
	doc, err := m.requirePolicy(req.ResourcePolicy)
	if err != nil {
		return err
	}
	why, broad, err := broadAccess(doc)
	if err != nil {
		return err
	}

	if err = m.authorizeValidate(ctx, req.SecretID); err != nil {
		return err
	}

	res := smapi.ValidateResourcePolicyResponse{
		PolicyValidationPassed: !broad,
		ValidationErrors:       []smapi.ValidationErrorsEntry{},
	}
	if broad {
		res.ValidationErrors = append(res.ValidationErrors, smapi.ValidationErrorsEntry{
			CheckName:    broadAccessCheck,
			ErrorMessage: "The resource policy grants broad access to the secret. " + why,
		})
	}
	return smapi.Write(ctx, res)
}

// optionalSecretID refuses a SecretId that is given but empty or longer than
// the API allows.
func optionalSecretID(secretID *string) error {
	switch {
	case secretID == nil:
		return nil
	case *secretID == "":
		return smapi.ErrTooShort("secretId", "", 1)
	default:
		return requireSecretID(*secretID)
	}
}

// authorizeValidate checks ValidateResourcePolicy's two actions on the
// secret secretID names, which must exist and not be scheduled for
// deletion, or on "*" without one.
func (m *Module) authorizeValidate(ctx gas.Context, secretID *string) error {
	const op = "ValidateResourcePolicy"
	actions := []string{"secretsmanager:ValidateResourcePolicy", "secretsmanager:PutResourcePolicy"}
	if secretID == nil {
		for _, action := range actions {
			if err := m.authorizeAll(ctx, op, action, true); err != nil {
				return err
			}
		}
		return nil
	}
	sctx := m.guardActions(ctx, op, *secretID, actions...)
	_, err := m.secrets.GetResourcePolicy(sctx, *secretID)
	return err
}

// requirePolicy returns the ResourcePolicy a request gave, refusing one that
// is missing, empty, longer than maxPolicyLen characters, or that does not
// parse as a resource-based policy. The length is checked first, so nothing
// longer than the API allows is parsed.
func (m *Module) requirePolicy(doc *string) (string, error) {
	switch {
	case doc == nil:
		return "", smapi.ErrInvalidParameter("ResourcePolicy is required.")
	case *doc == "":
		return "", smapi.ErrTooShort("resourcePolicy", "", 1)
	case utf8.RuneCountInString(*doc) > maxPolicyLen:
		return "", smapi.ErrTooLong("resourcePolicy", *doc, maxPolicyLen)
	}
	if err := m.authz.ParseResourcePolicy(*doc); err != nil {
		return "", err
	}
	return *doc, nil
}

// invalidPrincipal is the message of the MalformedPolicyDocumentException
// for a policy naming a user or role ARN that no user or role has. Secrets
// Manager documents the exception ("The resource policy has syntax errors.")
// but not this message; it is the one IAM and S3 give for the same policy.
const invalidPrincipal = "Invalid principal in policy"

// bindPolicy returns doc, a policy requirePolicy accepted, bound by
// m.principals: each user and role ARN in its principals replaced by the
// principal's unique ID, as AWS stores it. A user or role ARN that no user or
// role has is MalformedPolicyDocumentException; failing to ask identity is an
// internal error, so the policy is never stored unbound. The bound document
// is held to maxPolicyLen, as requirePolicy holds the request's, since a
// unique ID may be longer than the ARN it replaces, and is parsed as the one
// checks will evaluate.
func (m *Module) bindPolicy(ctx context.Context, doc string) (string, error) {
	bound, err := m.principals.Bind(ctx, doc)
	if errors.Is(err, principals.ErrInvalidPrincipal) {
		return "", smapi.ErrMalformedPolicy(invalidPrincipal)
	}
	if err != nil {
		return "", fmt.Errorf("bind the principals of the resource policy: %w", err)
	}
	if utf8.RuneCountInString(bound) > maxPolicyLen {
		return "", smapi.ErrTooLong("resourcePolicy", bound, maxPolicyLen)
	}
	if err = m.authz.ParseResourcePolicy(bound); err != nil {
		// Not wrapped: the binding is at fault, not the request, so this is
		// an internal error rather than the request's MalformedPolicy.
		return "", fmt.Errorf("the bound resource policy does not parse: %s", err.Error())
	}
	return bound, nil
}

// checkPolicyName refuses a PolicyName that breaks the model's constraints,
// with ValidationException, or that is not "default": PutResourcePolicy and
// DeleteResourcePolicy answer that InvalidParameterException, and
// GetResourcePolicy, with get set, ResourceNotFoundException ("If you
// specify a name other than default and no policy with that name exists").
// An absent name is "default".
func checkPolicyName(name *string, get bool) error {
	if name == nil {
		return nil
	}
	switch n := *name; {
	case n == "":
		return smapi.ErrTooShort("policyName", n, 1)
	case len(n) > maxPolicyNameLen:
		return smapi.ErrTooLong("policyName", n, maxPolicyNameLen)
	case !validPolicyName(n):
		return smapi.ErrPattern("policyName", n, policyNamePattern)
	case n == defaultPolicyName:
		return nil
	case get:
		return smapi.ErrResourceNotFound(
			"Secrets Manager can't find the specified resource policy.",
		)
	default:
		return smapi.ErrInvalidParameter(
			"You can only attach the default policy; PolicyName must be default.")
	}
}

// validPolicyName reports whether n matches policyNamePattern.
func validPolicyName(n string) bool {
	for _, r := range n {
		ok := r == '-' || r == '_' ||
			('0' <= r && r <= '9') || ('A' <= r && r <= 'Z') || ('a' <= r && r <= 'z')
		if !ok {
			return false
		}
	}
	return true
}

// broadAccess is authz.BroadAccess for a request's policy.
func broadAccess(doc string) (string, bool, error) {
	why, broad, err := authz.BroadAccess([]byte(doc))
	if err != nil {
		return "", false, fmt.Errorf("check the resource policy for broad access: %w", err)
	}
	return why, broad, nil
}

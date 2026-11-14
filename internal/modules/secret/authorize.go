package secret

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"tule.dev/secret-store/internal/authz"
	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/smapi"
)

// authorizeAll checks action, one of op's checks, on "*", for an action the
// reference gives no resource type, or one made on no secret. No resource
// policy applies. ListSecrets lists the store's own secrets, so it is checked
// as on the store's account, which a principal of another account needs a
// resource policy for and cannot have. callersAccount checks it instead as on
// the caller's own account, for an action that reads nothing of the store's
// by itself: BatchGetSecretValue's own action, whose secrets are each checked
// with their own policy, ValidateResourcePolicy without a secret, and
// GetRandomPassword.
func (m *Module) authorizeAll(ctx context.Context, op, action string, callersAccount bool) error {
	return m.authz.Check(ctx, authz.Request{
		Operation:      op,
		Action:         action,
		Resource:       "*",
		Shown:          "*",
		CallersAccount: callersAccount,
	})
}

// guardSecret returns ctx carrying the check of op's own action on the
// secret secretID names, with keys besides the secret's own (see guard).
func (m *Module) guardSecret(
	ctx context.Context,
	op, secretID string,
	keys map[string][]string,
	also ...contracts.Check,
) context.Context {
	return m.guard(ctx, op, authz.Operations[op][0].Action, secretID, keys, also...)
}

// guard returns ctx carrying the check of action, one of op's checks, on the
// secret secretID names, for the store to run once it has resolved that
// secret, under the lock it acts under (contracts.Check). The check and the
// operation therefore see one secret: nothing can swap the secret a request
// resolves to between the two. A secret that does not exist is checked on
// the ARN MissingSecretARN gives, so a caller who may not touch it learns
// nothing of whether it exists. The checks also run on the same secret, and
// only once the request is allowed, so what they report of the secret is
// told only to a caller allowed the action. The root principal is not
// evaluated: its context carries an explicit allow-all check.
//
// Every store call an operation makes with the returned context runs the
// check; an operation must make its store call with it.
func (m *Module) guard(
	ctx context.Context,
	op, action, secretID string,
	keys map[string][]string,
	also ...contracts.Check,
) context.Context {
	if authz.IsRoot(ctx) {
		return contracts.Unchecked(ctx)
	}
	return contracts.WithCheck(ctx, func(found *contracts.SecretDetail) error {
		if err := m.checkSecret(ctx, op, action, secretID, keys, found); err != nil {
			return err
		}
		// Only an allowed caller learns what the further checks say of the
		// secret, such as which tag keys it holds.
		for _, c := range also {
			if err := c(found); err != nil {
				return err
			}
		}
		return nil
	})
}

// guardActions is guard for an operation authorized as several actions on
// one secret, each checked in turn on the secret the store resolves.
func (m *Module) guardActions(
	ctx context.Context,
	op, secretID string,
	actions ...string,
) context.Context {
	if authz.IsRoot(ctx) {
		return contracts.Unchecked(ctx)
	}
	return contracts.WithCheck(ctx, func(found *contracts.SecretDetail) error {
		for _, action := range actions {
			if err := m.checkSecret(ctx, op, action, secretID, nil, found); err != nil {
				return err
			}
		}
		return nil
	})
}

// checkSecret checks action on found, the secret the store resolved secretID
// to, or nil when there is none, with the secret's own keys and keys, and
// with the resource policy stored in the same record: the policy evaluated is
// the one of the secret acted on, read under the same lock.
func (m *Module) checkSecret(
	ctx context.Context,
	op, action, secretID string,
	keys map[string][]string,
	found *contracts.SecretDetail,
) error {
	if account, foreign := m.authz.ForeignAccount(ctx); foreign &&
		!strings.HasPrefix(secretID, "arn:") {
		return m.checkForeignName(ctx, op, action, secretID, account, keys)
	}
	arn, tags, err := m.secretFacts(secretID, found)
	if err != nil {
		return err
	}
	all := m.authz.SecretKeys(arn, tags)
	for k, v := range keys {
		all[k] = v
	}
	req := authz.Request{
		Operation: op,
		Action:    action,
		Resource:  arn,
		Shown:     secretID,
		Keys:      all,
	}
	if found != nil {
		req.Policy = found.ResourcePolicy
	}
	return m.authz.Check(ctx, req)
}

// checkForeignName answers a principal of another account that names a
// secret by name rather than ARN. Secrets Manager reads a name in the
// caller's own account ("To retrieve a secret from another account, you must
// use an ARN.", GetSecretValue SecretId, API reference), and the store holds
// no secret of that account, so the request is checked as on a missing
// secret there, arn:aws:secretsmanager:<region>:<caller's account>:secret:<name>,
// with no resource policy, and an allowed one is answered
// ResourceNotFoundException. The store's own secret of that name, if any, is
// never looked at: neither its policy nor its existence decides the answer.
func (m *Module) checkForeignName(
	ctx context.Context,
	op, action, secretID, account string,
	keys map[string][]string,
) error {
	arn := m.authz.SecretARNIn(account, secretID)
	all := m.authz.SecretKeys(arn, nil)
	for k, v := range keys {
		all[k] = v
	}
	err := m.authz.Check(ctx, authz.Request{
		Operation:      op,
		Action:         action,
		Resource:       arn,
		Shown:          secretID,
		Keys:           all,
		CallersAccount: true,
	})
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: %s in account %s", contracts.ErrSecretNotFound, secretID, account)
}

// secretFacts returns the ARN and tags of detail, the secret the store
// resolved secretID to, or for nil the ARN a missing secret is checked on
// and no tags. The ARN is rebuilt from the
// store's own partition, region and account and the secret the operation
// will act on, never taken from the request. A SecretId that is an ARN of
// another partition, region or account names no secret here and fails with
// contracts.ErrSecretNotFound, answered ResourceNotFoundException without
// any evaluation, as a regional Secrets Manager endpoint answers for a
// secret it does not hold.
//
// The secret's tags are always loaded, whatever the policies say: deciding
// from a policy's text which keys it reads would let an escaped key name
// slip past. A stored secret with a repeated tag key, which only a version
// before tag keys were checked could write, fails the check rather than
// supply one of its values; so does one with keys that differ only by case,
// which a root write may store and IAM would read as one key.
func (m *Module) secretFacts(
	secretID string,
	detail *contracts.SecretDetail,
) (string, map[string]string, error) {
	if detail == nil {
		arn, ok := m.authz.MissingSecretARN(secretID)
		if !ok {
			return "", nil, fmt.Errorf("%w: %s", contracts.ErrSecretNotFound, secretID)
		}
		return arn, nil, nil
	}

	arn, err := m.authz.SecretARN(detail.Name, detail.ARN)
	if err != nil {
		return "", nil, err
	}
	if err = contracts.CheckTagKeysFold(detail.Tags); err != nil {
		// Not wrapped: the sentinel would answer it as the request's own
		// InvalidParameterException, where it is the store's fault.
		return "", nil, fmt.Errorf("secret %s carries stored tags it cannot be checked on: %s",
			detail.Name, err.Error())
	}
	tags := make(map[string]string, len(detail.Tags))
	for _, t := range detail.Tags {
		tags[t.Key] = t.Value
	}
	return arn, tags, nil
}

// authorizeCreate checks CreateSecret on arn, the ARN the secret will have,
// and TagResource on it too when the request has tags.
func (m *Module) authorizeCreate(
	ctx context.Context,
	req smapi.CreateSecretRequest,
	arn string,
) error {
	const op = "CreateSecret"
	if authz.IsRoot(ctx) {
		return nil
	}

	tagKeys := authz.TagKeys(req.Tags)
	keys := map[string][]string{"secretsmanager:Name": {req.Name}}
	if req.Description != "" {
		keys["secretsmanager:Description"] = []string{req.Description}
	}
	if req.KmsKeyID != "" {
		keys["secretsmanager:KmsKeyId"] = []string{req.KmsKeyID}
	}
	for k, v := range tagKeys {
		keys[k] = v
	}
	err := m.authz.Check(ctx, authz.Request{
		Operation: op, Action: "secretsmanager:CreateSecret",
		Resource: arn, Shown: req.Name, Keys: keys,
	})
	if err != nil || len(req.Tags) == 0 {
		return err
	}

	tagKeys["secretsmanager:SecretId"] = []string{arn}
	return m.authz.Check(ctx, authz.Request{
		Operation: op, Action: "secretsmanager:TagResource",
		Resource: arn, Shown: req.Name, Keys: tagKeys,
	})
}

// optional adds key with value to keys, unless value is empty: a condition
// key the request carries only when the caller gave it.
func optional(keys map[string][]string, key, value string) map[string][]string {
	if value == "" {
		return keys
	}
	if keys == nil {
		keys = map[string][]string{}
	}
	keys[key] = []string{value}
	return keys
}

// deleteKeys returns DeleteSecret's own keys: ForceDeleteWithoutRecovery when
// it is set and RecoveryWindowInDays when it is given.
func deleteKeys(req smapi.DeleteSecretRequest) map[string][]string {
	var keys map[string][]string
	if req.ForceDeleteWithoutRecovery {
		keys = optional(keys, "secretsmanager:ForceDeleteWithoutRecovery", "true")
	}
	if req.RecoveryWindowInDays != nil {
		keys = optional(keys, "secretsmanager:RecoveryWindowInDays",
			strconv.FormatInt(*req.RecoveryWindowInDays, 10))
	}
	return keys
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

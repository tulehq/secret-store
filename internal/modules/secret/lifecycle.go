package secret

import (
	"context"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/authz"
	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/smapi"
)

// The recovery window Secrets Manager allows a scheduled deletion to be given.
const (
	minRecoveryDays = 7
	maxRecoveryDays = 30
)

func (m *Module) createSecret(ctx gas.Context) error {
	req, err := decode[smapi.CreateSecretRequest](ctx)
	if err != nil {
		return err
	}
	if req.Name == "" {
		return smapi.ErrInvalidParameter("Name is required.")
	}
	if len(req.Name) > maxNameLen {
		return smapi.ErrTooLong("name", req.Name, maxNameLen)
	}
	// A repeated tag key is refused before the request is evaluated, so it
	// never becomes a multivalued aws:RequestTag.
	if err = contracts.CheckTagKeys(tagsOf(req.Tags)); err != nil {
		return err
	}
	if err = checkFoldedTagKeys(ctx, req.Tags); err != nil {
		return err
	}

	// The ARN is minted first, so the request is authorized on the ARN the
	// secret will have, random suffix included, as AWS documents a
	// "secret:<name>-??????" resource granting the creation of a secret
	// that does not exist yet.
	arn, err := m.secrets.NewSecretARN(req.Name)
	if err != nil {
		return err
	}
	if err = m.authorizeCreate(ctx, req, arn); err != nil {
		return err
	}

	out, err := m.secrets.CreateSecret(ctx, contracts.CreateSecretInput{
		ARN:         arn,
		Name:        req.Name,
		Description: req.Description,
		KmsKeyID:    req.KmsKeyID,
		VersionID:   req.ClientRequestToken,
		Payload:     payloadOf(req.SecretString, req.SecretBinary),
		Tags:        tagsOf(req.Tags),
	})
	if err != nil {
		return err
	}

	return smapi.Write(ctx, smapi.CreateSecretResponse{
		SecretRefResponse: secretRef(out.SecretRef),
		VersionID:         out.VersionID,
	})
}

func (m *Module) updateSecret(ctx gas.Context) error {
	req, err := decode[smapi.UpdateSecretRequest](ctx)
	if err != nil {
		return err
	}
	if err = requireSecretID(req.SecretID); err != nil {
		return err
	}
	var keys map[string][]string
	if req.Description != nil {
		keys = map[string][]string{"secretsmanager:Description": {*req.Description}}
	}
	keys = optional(keys, "secretsmanager:KmsKeyId", deref(req.KmsKeyID))
	sctx := m.guardSecret(ctx, "UpdateSecret", req.SecretID, keys)

	out, err := m.secrets.UpdateSecret(sctx, contracts.UpdateSecretInput{
		SecretID:    req.SecretID,
		Description: req.Description,
		KmsKeyID:    req.KmsKeyID,
		VersionID:   req.ClientRequestToken,
		Payload:     payloadOf(req.SecretString, req.SecretBinary),
	})
	if err != nil {
		return err
	}

	return smapi.Write(ctx, smapi.CreateSecretResponse{
		SecretRefResponse: secretRef(out.SecretRef),
		VersionID:         out.VersionID,
	})
}

func (m *Module) describeSecret(ctx gas.Context) error {
	req, err := decode[smapi.SecretIDRequest](ctx)
	if err != nil {
		return err
	}
	if err = requireSecretID(req.SecretID); err != nil {
		return err
	}
	sctx := m.guardSecret(ctx, "DescribeSecret", req.SecretID, nil)

	out, err := m.secrets.DescribeSecret(sctx, req.SecretID)
	if err != nil {
		return err
	}

	return smapi.Write(ctx, smapi.DescribeSecretResponse{
		SecretRefResponse:  secretRef(out.SecretRef),
		Description:        out.Description,
		KmsKeyID:           out.KmsKeyID,
		Tags:               wireTags(out.Tags),
		CreatedDate:        smapi.Stamp(out.CreatedDate),
		LastChangedDate:    smapi.Stamp(out.LastChangedDate),
		LastAccessedDate:   smapi.Stamp(out.LastAccessedDate),
		DeletedDate:        smapi.Stamp(out.DeletedDate),
		VersionIDsToStages: out.VersionStages,
	})
}

func (m *Module) deleteSecret(ctx gas.Context) error {
	req, err := decode[smapi.DeleteSecretRequest](ctx)
	if err != nil {
		return err
	}
	if err = requireSecretID(req.SecretID); err != nil {
		return err
	}

	window, err := recoveryWindow(req)
	if err != nil {
		return err
	}
	sctx := m.guardSecret(ctx, "DeleteSecret", req.SecretID, deleteKeys(req))

	out, err := m.secrets.DeleteSecret(sctx, contracts.DeleteSecretInput{
		SecretID:       req.SecretID,
		RecoveryWindow: window,
		Force:          req.ForceDeleteWithoutRecovery,
	})
	if err != nil {
		return err
	}

	return smapi.Write(ctx, smapi.DeleteSecretResponse{
		SecretRefResponse: secretRef(out.SecretRef),
		DeletionDate:      smapi.Stamp(out.DeletionDate),
	})
}

// recoveryWindow validates a deletion request's recovery window. Asking for
// one and asking to skip it at the same time is a contradiction Secrets
// Manager rejects rather than resolving.
func recoveryWindow(req smapi.DeleteSecretRequest) (time.Duration, error) {
	if req.RecoveryWindowInDays == nil {
		return 0, nil
	}
	if req.ForceDeleteWithoutRecovery {
		return 0, smapi.ErrInvalidParameter(
			"You can't use ForceDeleteWithoutRecovery together with RecoveryWindowInDays.")
	}

	days := *req.RecoveryWindowInDays
	if days < minRecoveryDays || days > maxRecoveryDays {
		return 0, smapi.ErrInvalidParameter(
			"RecoveryWindowInDays must be between 7 and 30 days.")
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

func (m *Module) restoreSecret(ctx gas.Context) error {
	req, err := decode[smapi.SecretIDRequest](ctx)
	if err != nil {
		return err
	}
	if err = requireSecretID(req.SecretID); err != nil {
		return err
	}
	sctx := m.guardSecret(ctx, "RestoreSecret", req.SecretID, nil)

	out, err := m.secrets.RestoreSecret(sctx, req.SecretID)
	if err != nil {
		return err
	}

	return smapi.Write(ctx, secretRef(*out))
}

func (m *Module) tagResource(ctx gas.Context) error {
	req, err := decode[smapi.TagResourceRequest](ctx)
	if err != nil {
		return err
	}
	if err = requireSecretID(req.SecretID); err != nil {
		return err
	}
	if err = contracts.CheckTagKeys(tagsOf(req.Tags)); err != nil {
		return err
	}
	if err = checkFoldedTagKeys(ctx, req.Tags); err != nil {
		return err
	}
	sctx := m.guardSecret(ctx, "TagResource", req.SecretID, authz.TagKeys(req.Tags),
		func(found *contracts.SecretDetail) error {
			if found == nil {
				return nil
			}
			return contracts.CheckTagKeysAgainst(tagsOf(req.Tags), found.Tags)
		})

	if _, err = m.secrets.TagSecret(sctx, req.SecretID, tagsOf(req.Tags)); err != nil {
		return err
	}

	// TagResource answers with an empty document.
	return smapi.Write(ctx, smapi.EmptyResponse{})
}

func (m *Module) untagResource(ctx gas.Context) error {
	req, err := decode[smapi.UntagResourceRequest](ctx)
	if err != nil {
		return err
	}
	if err = requireSecretID(req.SecretID); err != nil {
		return err
	}
	var keys map[string][]string
	if len(req.TagKeys) > 0 {
		keys = map[string][]string{"aws:TagKeys": req.TagKeys}
	}
	sctx := m.guardSecret(ctx, "UntagResource", req.SecretID, keys)

	if _, err = m.secrets.UntagSecret(sctx, req.SecretID, req.TagKeys); err != nil {
		return err
	}

	return smapi.Write(ctx, smapi.EmptyResponse{})
}

// checkFoldedTagKeys refuses, for an evaluated principal, tags whose keys
// differ only by case, which IAM would read as one key with two values. A
// root write is not evaluated, and is unchanged.
func checkFoldedTagKeys(ctx context.Context, tags []smapi.Tag) error {
	if authz.IsRoot(ctx) {
		return nil
	}
	return contracts.CheckTagKeysFold(tagsOf(tags))
}

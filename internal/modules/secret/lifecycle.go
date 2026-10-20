package secret

import (
	"time"

	"github.com/gasmod/gas"

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

	out, err := m.secrets.CreateSecret(ctx, contracts.CreateSecretInput{
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

	out, err := m.secrets.UpdateSecret(ctx, contracts.UpdateSecretInput{
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

	out, err := m.secrets.DescribeSecret(ctx, req.SecretID)
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

	out, err := m.secrets.DeleteSecret(ctx, contracts.DeleteSecretInput{
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

	out, err := m.secrets.RestoreSecret(ctx, req.SecretID)
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

	if _, err = m.secrets.TagSecret(ctx, req.SecretID, tagsOf(req.Tags)); err != nil {
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

	if _, err = m.secrets.UntagSecret(ctx, req.SecretID, req.TagKeys); err != nil {
		return err
	}

	return smapi.Write(ctx, smapi.EmptyResponse{})
}

package secret

import (
	"net/http"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/smapi"
)

func (m *Module) getSecretValue(ctx gas.Context) error {
	req, err := decode[smapi.GetSecretValueRequest](ctx)
	if err != nil {
		return err
	}
	if err = requireSecretID(req.SecretID); err != nil {
		return err
	}

	out, err := m.secrets.GetSecretValue(ctx, contracts.GetSecretValueInput{
		SecretID:     req.SecretID,
		VersionID:    req.VersionID,
		VersionStage: req.VersionStage,
	})
	if err != nil {
		return err
	}

	return smapi.Write(ctx, smapi.GetSecretValueResponse{
		SecretRefResponse: secretRef(out.SecretRef),
		VersionID:         out.VersionID,
		VersionStages:     out.VersionStages,
		SecretString:      out.Payload.String,
		SecretBinary:      out.Payload.Binary,
		CreatedDate:       smapi.Stamp(out.CreatedDate),
	})
}

func (m *Module) putSecretValue(ctx gas.Context) error {
	req, err := decode[smapi.PutSecretValueRequest](ctx)
	if err != nil {
		return err
	}
	if err = requireSecretID(req.SecretID); err != nil {
		return err
	}

	out, err := m.secrets.PutSecretValue(ctx, contracts.PutSecretValueInput{
		SecretID:      req.SecretID,
		VersionID:     req.ClientRequestToken,
		Payload:       payloadOf(req.SecretString, req.SecretBinary),
		VersionStages: req.VersionStages,
	})
	if err != nil {
		return err
	}

	return smapi.Write(ctx, smapi.PutSecretValueResponse{
		SecretRefResponse: secretRef(out.SecretRef),
		VersionID:         out.VersionID,
		VersionStages:     out.VersionStages,
	})
}

// batchGetSecretValue reads several secrets in one call. A secret that cannot
// be read is reported in Errors rather than failing the whole call, which is
// what the API promises; only a request this service cannot serve at all
// fails outright.
func (m *Module) batchGetSecretValue(ctx gas.Context) error {
	req, err := decode[smapi.BatchGetSecretValueRequest](ctx)
	if err != nil {
		return err
	}
	if err = rejectFilters(req.Filters); err != nil {
		return err
	}
	if req.NextToken != "" {
		return smapi.NewError(http.StatusBadRequest, smapi.TypeInvalidNextToken,
			"BatchGetSecretValue is not paginated by this service; it answers in one page.")
	}
	if len(req.SecretIDList) == 0 {
		return smapi.ErrInvalidParameter("SecretIdList is required.")
	}

	res := smapi.BatchGetSecretValueResponse{
		SecretValues: make([]smapi.BatchSecretValue, 0, len(req.SecretIDList)),
	}
	for _, secretID := range req.SecretIDList {
		out, gErr := m.secrets.GetSecretValue(ctx, contracts.GetSecretValueInput{
			SecretID: secretID,
		})
		if gErr != nil {
			apiErr := smapi.ToError(ctx, gErr)
			res.Errors = append(res.Errors, smapi.BatchError{
				SecretID:  secretID,
				ErrorCode: apiErr.Type,
				Message:   apiErr.Message,
			})
			continue
		}
		res.SecretValues = append(res.SecretValues, smapi.BatchSecretValue{
			SecretRefResponse: secretRef(out.SecretRef),
			VersionID:         out.VersionID,
			VersionStages:     out.VersionStages,
			SecretString:      out.Payload.String,
			SecretBinary:      out.Payload.Binary,
			CreatedDate:       smapi.Stamp(out.CreatedDate),
		})
	}

	return smapi.Write(ctx, res)
}

func (m *Module) updateSecretVersionStage(ctx gas.Context) error {
	req, err := decode[smapi.UpdateSecretVersionStageRequest](ctx)
	if err != nil {
		return err
	}
	if err = requireSecretID(req.SecretID); err != nil {
		return err
	}
	if req.VersionStage == "" {
		return smapi.ErrInvalidParameter("VersionStage is required.")
	}
	if req.MoveToVersionID == "" && req.RemoveFromVersionID == "" {
		return smapi.ErrInvalidParameter(
			"One of MoveToVersionId and RemoveFromVersionId is required.")
	}

	out, err := m.secrets.UpdateSecretVersionStage(
		ctx,
		contracts.UpdateSecretVersionStageInput{
			SecretID:     req.SecretID,
			VersionStage: req.VersionStage,
			MoveTo:       req.MoveToVersionID,
			RemoveFrom:   req.RemoveFromVersionID,
		},
	)
	if err != nil {
		return err
	}

	return smapi.Write(ctx, secretRef(*out))
}

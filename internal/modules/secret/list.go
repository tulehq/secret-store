package secret

import (
	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/smapi"
)

func (m *Module) listSecrets(ctx gas.Context) error {
	req, err := decode[smapi.ListSecretsRequest](ctx)
	if err != nil {
		return err
	}
	if err = rejectFilters(req.Filters); err != nil {
		return err
	}
	if err = rejectSort(req.SortBy, req.SortOrder); err != nil {
		return err
	}

	out, err := m.secrets.ListSecrets(ctx, contracts.ListSecretsInput{
		NextToken:      req.NextToken,
		MaxResults:     req.MaxResults,
		IncludeDeleted: req.IncludePlannedDeletion,
	})
	if err != nil {
		return err
	}

	res := smapi.ListSecretsResponse{
		NextToken:  out.NextToken,
		SecretList: make([]smapi.SecretListEntry, 0, len(out.Secrets)),
	}
	for _, detail := range out.Secrets {
		res.SecretList = append(res.SecretList, smapi.SecretListEntry{
			SecretRefResponse:      secretRef(detail.SecretRef),
			Description:            detail.Description,
			KmsKeyID:               detail.KmsKeyID,
			Tags:                   wireTags(detail.Tags),
			CreatedDate:            smapi.Stamp(detail.CreatedDate),
			LastChangedDate:        smapi.Stamp(detail.LastChangedDate),
			LastAccessedDate:       smapi.Stamp(detail.LastAccessedDate),
			DeletedDate:            smapi.Stamp(detail.DeletedDate),
			SecretVersionsToStages: detail.VersionStages,
		})
	}

	return smapi.Write(ctx, res)
}

func (m *Module) listSecretVersionIDs(ctx gas.Context) error {
	req, err := decode[smapi.ListSecretVersionIDsRequest](ctx)
	if err != nil {
		return err
	}
	if err = requireSecretID(req.SecretID); err != nil {
		return err
	}

	out, err := m.secrets.ListSecretVersions(ctx, contracts.ListSecretVersionsInput{
		SecretID:          req.SecretID,
		NextToken:         req.NextToken,
		MaxResults:        req.MaxResults,
		IncludeDeprecated: req.IncludeDeprecated,
	})
	if err != nil {
		return err
	}

	res := smapi.ListSecretVersionIDsResponse{
		SecretRefResponse: secretRef(out.SecretRef),
		NextToken:         out.NextToken,
		Versions:          make([]smapi.VersionsListEntry, 0, len(out.Versions)),
	}
	for _, version := range out.Versions {
		res.Versions = append(res.Versions, smapi.VersionsListEntry{
			VersionID:     version.VersionID,
			VersionStages: version.VersionStages,
			CreatedDate:   smapi.Stamp(version.CreatedDate),
		})
	}

	return smapi.Write(ctx, res)
}

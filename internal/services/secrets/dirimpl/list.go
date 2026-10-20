package dirimpl

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"time"

	"tule.dev/secret-store/internal/contracts"
)

// dayDuration is the granularity Secrets Manager reports a secret's last
// access with.
const dayDuration = 24 * time.Hour

// ListSecrets pages through the stored secrets in name order.
func (s *Service) ListSecrets(
	_ context.Context,
	in contracts.ListSecretsInput,
) (*contracts.ListSecretsOutput, error) {
	after, err := decodeToken(in.NextToken)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	recs, err := s.all()
	if err != nil {
		return nil, err
	}

	size := pageSize(in.MaxResults)
	out := contracts.ListSecretsOutput{Secrets: make([]contracts.SecretDetail, 0, size)}

	for _, rec := range recs {
		switch {
		case rec.deleted() && !in.IncludeDeleted:
			continue
		case after != "" && rec.Name <= after:
			continue
		case len(out.Secrets) == size:
			// One secret past the page: there is more to come.
			out.NextToken = encodeToken(out.Secrets[size-1].Name)
			return &out, nil
		}
		out.Secrets = append(out.Secrets, rec.detail())
	}

	return &out, nil
}

// ListSecretVersions pages through one secret's versions, newest first.
func (s *Service) ListSecretVersions(
	_ context.Context,
	in contracts.ListSecretVersionsInput,
) (*contracts.ListSecretVersionsOutput, error) {
	after, err := decodeToken(in.NextToken)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.resolveLive(in.SecretID)
	if err != nil {
		return nil, err
	}

	versions := slices.Clone(rec.Versions)
	slices.Reverse(versions)

	size := pageSize(in.MaxResults)
	out := contracts.ListSecretVersionsOutput{
		SecretRef: rec.ref(),
		Versions:  make([]contracts.VersionInfo, 0, size),
	}

	skipping := after != ""
	for _, version := range versions {
		switch {
		case skipping:
			skipping = version.VersionID != after
			continue
		case len(version.Stages) == 0 && !in.IncludeDeprecated:
			continue
		case len(out.Versions) == size:
			out.NextToken = encodeToken(out.Versions[size-1].VersionID)
			return &out, nil
		}
		out.Versions = append(out.Versions, contracts.VersionInfo{
			VersionID:     version.VersionID,
			VersionStages: slices.Clone(version.Stages),
			CreatedDate:   version.CreatedDate,
		})
	}

	return &out, nil
}

// encodeToken returns the pagination token that resumes a listing after the
// last item of a page. It is opaque to clients, so it is encoded rather than
// handing out the name or version ID as is.
func encodeToken(after string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(after))
}

// decodeToken returns the item a listing should resume after, or "" for an
// empty token.
func decodeToken(token string) (string, error) {
	if token == "" {
		return "", nil
	}
	after, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("%w: %s", contracts.ErrInvalidToken, token)
	}
	return string(after), nil
}

package dirimpl

import (
	"context"

	"tule.dev/secret-store/internal/contracts"
)

// PutResourcePolicy stores doc as the secret's resource policy, in the
// secret's own file, so the policy a check evaluates is always the one stored
// with the secret it resolves. A secret scheduled for deletion is refused, as
// Secrets Manager lists for the operation.
func (s *Service) PutResourcePolicy(
	ctx context.Context,
	secretID, doc string,
) (*contracts.SecretRef, error) {
	return s.setPolicy(ctx, secretID, doc)
}

// DeleteResourcePolicy removes the secret's resource policy. A secret with
// none is left as it is and answered as a success.
func (s *Service) DeleteResourcePolicy(
	ctx context.Context,
	secretID string,
) (*contracts.SecretRef, error) {
	return s.setPolicy(ctx, secretID, "")
}

// GetResourcePolicy returns the secret's resource policy. A secret scheduled
// for deletion is refused, as Secrets Manager lists for the operation.
func (s *Service) GetResourcePolicy(
	ctx context.Context,
	secretID string,
) (*contracts.SecretPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.resolveLive(ctx, secretID)
	if err != nil {
		return nil, err
	}
	return &contracts.SecretPolicy{SecretRef: rec.ref(), Policy: rec.ResourcePolicy}, nil
}

func (s *Service) setPolicy(
	ctx context.Context,
	secretID, doc string,
) (*contracts.SecretRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.resolveLive(ctx, secretID)
	if err != nil {
		return nil, err
	}
	ref := rec.ref()
	if rec.ResourcePolicy == doc {
		return &ref, nil
	}

	rec.ResourcePolicy = doc
	rec.LastChangedDate = s.now().UTC()
	if err = s.write(rec); err != nil {
		return nil, err
	}
	return &ref, nil
}

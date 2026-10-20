package dirimpl

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"tule.dev/secret-store/internal/contracts"
)

// CreateSecret stores a new secret, with Payload as its AWSCURRENT version
// when the request carries one.
func (s *Service) CreateSecret(
	_ context.Context,
	in contracts.CreateSecretInput,
) (*contracts.SecretVersion, error) {
	if err := validateName(in.Name); err != nil {
		return nil, err
	}
	if !in.Payload.IsZero() {
		if err := checkPayload(in.Payload); err != nil {
			return nil, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.mustNotExist(in.Name); err != nil {
		return nil, err
	}

	arn, err := s.mintARN(in.Name)
	if err != nil {
		return nil, err
	}

	now := s.now().UTC()
	rec := &record{
		Name:            in.Name,
		ARN:             arn,
		Description:     in.Description,
		KmsKeyID:        in.KmsKeyID,
		Tags:            slices.Clone(in.Tags),
		CreatedDate:     now,
		LastChangedDate: now,
	}
	s.warnUnencrypted(rec)

	var version *contracts.SecretVersion
	if in.Payload.IsZero() {
		version = &contracts.SecretVersion{SecretRef: rec.ref()}
	} else if version, err = s.appendVersion(rec, in.VersionID, in.Payload, nil); err != nil {
		return nil, err
	}

	if err = s.write(rec); err != nil {
		return nil, err
	}
	return version, nil
}

// warnUnencrypted says once, for the secret being written, that the KMS key it
// asks for does nothing. The key is stored and reported back so a client sees
// its own setting, but the value next to it is in the clear, and that is worth
// saying out loud in a service whose whole job is standing in for one that
// encrypts.
func (s *Service) warnUnencrypted(rec *record) {
	if rec.KmsKeyID == "" {
		return
	}
	s.logger.Warn("secret names a KMS key, but this service stores values unencrypted").
		Str("secret", rec.Name).Str("kms_key_id", rec.KmsKeyID).Send()
}

// mustNotExist reports whether a secret of this name can be created.
func (s *Service) mustNotExist(name string) error {
	rec, err := s.read(name)
	switch {
	case err == nil && rec.deleted():
		return fmt.Errorf("%w: %s", contracts.ErrSecretDeleted, name)
	case err == nil:
		return fmt.Errorf("%w: %s", contracts.ErrSecretExists, name)
	case errorIsNotFound(err):
		return nil
	default:
		return err
	}
}

// UpdateSecret changes a secret's description and, when the request carries a
// value, stores it as a new AWSCURRENT version.
func (s *Service) UpdateSecret(
	_ context.Context,
	in contracts.UpdateSecretInput,
) (*contracts.SecretVersion, error) {
	if !in.Payload.IsZero() {
		if err := checkPayload(in.Payload); err != nil {
			return nil, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.resolveLive(in.SecretID)
	if err != nil {
		return nil, err
	}

	if in.Description != nil {
		rec.Description = *in.Description
	}
	if in.KmsKeyID != nil {
		rec.KmsKeyID = *in.KmsKeyID
		s.warnUnencrypted(rec)
	}

	version, err := s.updatedVersion(rec, in)
	if err != nil {
		return nil, err
	}

	rec.LastChangedDate = s.now().UTC()
	if err = s.write(rec); err != nil {
		return nil, err
	}
	return version, nil
}

// updatedVersion stores the value an update carries, if it carries one, and
// returns the version the call answers with.
//
// A retried update arrives with the version ID of the call it repeats, so it
// answers with that version rather than storing a second copy of the same
// value under a reused ID. The rest of such a call still applies: a
// description or a key sent with it is not dropped on the floor.
func (s *Service) updatedVersion(
	rec *record,
	in contracts.UpdateSecretInput,
) (*contracts.SecretVersion, error) {
	if in.Payload.IsZero() {
		return &contracts.SecretVersion{SecretRef: rec.ref()}, nil
	}

	stored, err := storedVersion(rec, in.VersionID, in.Payload)
	if stored != nil || err != nil {
		return stored, err
	}

	return s.appendVersion(rec, in.VersionID, in.Payload, nil)
}

// DescribeSecret reports a secret's metadata. It is one of the two operations
// a secret scheduled for deletion still answers, the other being
// RestoreSecret.
func (s *Service) DescribeSecret(
	_ context.Context,
	secretID string,
) (*contracts.SecretDetail, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.resolve(secretID)
	if err != nil {
		return nil, err
	}

	detail := rec.detail()
	return &detail, nil
}

// DeleteSecret schedules a secret for deletion, or removes it outright when
// the request asks to skip the recovery window.
//
// A scheduled secret is kept, and keeps answering DescribeSecret, until
// RestoreSecret brings it back; nothing here sweeps it up once its window
// passes, since the service holds no state between runs beyond these files.
func (s *Service) DeleteSecret(
	_ context.Context,
	in contracts.DeleteSecretInput,
) (*contracts.DeletedSecret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if in.Force {
		return s.forceDelete(in.SecretID)
	}

	rec, err := s.resolveLive(in.SecretID)
	if err != nil {
		return nil, err
	}

	now := s.now().UTC()
	window := in.RecoveryWindow
	if window == 0 {
		window = contracts.DefaultRecoveryWindow
	}
	rec.DeletedDate = now.Add(window)
	rec.LastChangedDate = now

	if err = s.write(rec); err != nil {
		return nil, err
	}
	return &contracts.DeletedSecret{SecretRef: rec.ref(), DeletionDate: rec.DeletedDate}, nil
}

// forceDelete removes a secret outright, with no recovery window.
//
// It accepts a secret that is already scheduled for deletion, and one that
// does not exist at all: "If you forcibly delete an already deleted or
// nonexistent secret, the operation does not fail." For a secret it cannot
// find there is no ARN to report, so the identifier the caller gave is echoed
// back in its place.
func (s *Service) forceDelete(secretID string) (*contracts.DeletedSecret, error) {
	now := s.now().UTC()

	rec, err := s.resolve(secretID)
	switch {
	case errorIsNotFound(err):
		return &contracts.DeletedSecret{
			SecretRef:    echoRef(secretID),
			DeletionDate: now,
		}, nil
	case err != nil:
		return nil, err
	}

	if err = s.remove(rec.Name); err != nil {
		return nil, err
	}
	return &contracts.DeletedSecret{SecretRef: rec.ref(), DeletionDate: now}, nil
}

// echoRef reports an identifier back as the field it looks like, for an answer
// about a secret the store never had.
func echoRef(secretID string) contracts.SecretRef {
	if strings.HasPrefix(secretID, arnPrefix) {
		return contracts.SecretRef{ARN: secretID}
	}
	return contracts.SecretRef{Name: secretID}
}

// RestoreSecret cancels a scheduled deletion.
func (s *Service) RestoreSecret(
	_ context.Context,
	secretID string,
) (*contracts.SecretRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.resolve(secretID)
	if err != nil {
		return nil, err
	}
	if !rec.deleted() {
		return nil, fmt.Errorf("%w: %s", contracts.ErrSecretNotDeleted, rec.Name)
	}

	rec.DeletedDate = time.Time{}
	rec.LastChangedDate = s.now().UTC()

	if err = s.write(rec); err != nil {
		return nil, err
	}

	ref := rec.ref()
	return &ref, nil
}

// TagSecret adds tags to a secret, replacing the value of any key it already
// carries.
func (s *Service) TagSecret(
	_ context.Context,
	secretID string,
	tags []contracts.Tag,
) (*contracts.SecretRef, error) {
	return s.retag(secretID, func(rec *record) {
		for _, tag := range tags {
			if i := slices.IndexFunc(rec.Tags, func(t contracts.Tag) bool {
				return t.Key == tag.Key
			}); i >= 0 {
				rec.Tags[i].Value = tag.Value
				continue
			}
			rec.Tags = append(rec.Tags, tag)
		}
	})
}

// UntagSecret removes the named tags from a secret, ignoring keys it does not
// carry, as Secrets Manager does.
func (s *Service) UntagSecret(
	_ context.Context,
	secretID string,
	keys []string,
) (*contracts.SecretRef, error) {
	return s.retag(secretID, func(rec *record) {
		rec.Tags = slices.DeleteFunc(rec.Tags, func(t contracts.Tag) bool {
			return slices.Contains(keys, t.Key)
		})
	})
}

func (s *Service) retag(secretID string, apply func(*record)) (*contracts.SecretRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.resolveLive(secretID)
	if err != nil {
		return nil, err
	}

	apply(rec)
	rec.LastChangedDate = s.now().UTC()

	if err = s.write(rec); err != nil {
		return nil, err
	}

	ref := rec.ref()
	return &ref, nil
}

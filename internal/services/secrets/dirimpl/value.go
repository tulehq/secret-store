package dirimpl

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"tule.dev/secret-store/internal/contracts"
)

// GetSecretValue returns one version of a secret's value: the one the request
// names by version ID, or the one carrying the requested staging label, which
// defaults to AWSCURRENT.
func (s *Service) GetSecretValue(
	_ context.Context,
	in contracts.GetSecretValueInput,
) (*contracts.SecretValue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.resolveLive(in.SecretID)
	if err != nil {
		return nil, err
	}

	version, err := selectVersion(rec, in)
	if err != nil {
		return nil, err
	}

	if err = s.touchAccessed(rec); err != nil {
		return nil, err
	}

	return &contracts.SecretValue{
		SecretRef:     rec.ref(),
		VersionID:     version.VersionID,
		VersionStages: slices.Clone(version.Stages),
		Payload:       version.payload(),
		CreatedDate:   version.CreatedDate,
	}, nil
}

// selectVersion picks the version a read asks for. A version ID wins over a
// staging label, and when both are given the version must carry the label.
func selectVersion(
	rec *record,
	in contracts.GetSecretValueInput,
) (*recordVersion, error) {
	if in.VersionID != "" {
		version := rec.byID(in.VersionID)
		if version == nil {
			return nil, fmt.Errorf("%w: version %s of %s",
				contracts.ErrVersionNotFound, in.VersionID, rec.Name)
		}
		if in.VersionStage != "" && !slices.Contains(version.Stages, in.VersionStage) {
			return nil, fmt.Errorf("%w: version %s of %s does not carry %s",
				contracts.ErrVersionNotFound, in.VersionID, rec.Name, in.VersionStage)
		}
		return version, nil
	}

	stage := in.VersionStage
	if stage == "" {
		stage = contracts.StageCurrent
	}
	version := rec.byStage(stage)
	if version == nil {
		return nil, fmt.Errorf("%w: staging label %s of %s",
			contracts.ErrVersionNotFound, stage, rec.Name)
	}
	return version, nil
}

// touchAccessed records that the secret was read. Secrets Manager reports the
// last access as a date, so the file is only rewritten when the day changes,
// which keeps reads from writing on every call.
func (s *Service) touchAccessed(rec *record) error {
	now := s.now().UTC().Truncate(dayDuration)
	if rec.LastAccessedDate.Equal(now) {
		return nil
	}
	rec.LastAccessedDate = now
	return s.write(rec)
}

// PutSecretValue stores a new version of a secret's value. With no staging
// labels the new version becomes AWSCURRENT, which moves AWSPREVIOUS onto the
// version it replaces.
//
// Reusing a version ID with the same value is treated as a retry of the same
// write and returns the stored version, which is what makes a client request
// token safe to retry; reusing one with a different value is an error.
func (s *Service) PutSecretValue(
	_ context.Context,
	in contracts.PutSecretValueInput,
) (*contracts.SecretVersion, error) {
	if err := checkPayload(in.Payload); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.resolveLive(in.SecretID)
	if err != nil {
		return nil, err
	}

	stored, err := storedVersion(rec, in.VersionID, in.Payload)
	if stored != nil || err != nil {
		return stored, err
	}

	version, err := s.appendVersion(rec, in.VersionID, in.Payload, in.VersionStages)
	if err != nil {
		return nil, err
	}

	rec.LastChangedDate = s.now().UTC()
	if err = s.write(rec); err != nil {
		return nil, err
	}
	return version, nil
}

// checkPayload rejects a value that is neither a string nor binary, or both at
// once, and one larger than Secrets Manager would store.
func checkPayload(p contracts.Payload) error {
	if !p.Valid() {
		return contracts.ErrInvalidValue
	}
	if p.Size() > contracts.MaxValueSize {
		return fmt.Errorf("%w: %d bytes, limit %d",
			contracts.ErrValueTooLarge, p.Size(), contracts.MaxValueSize)
	}
	return nil
}

// storedVersion answers a write whose version ID a version already holds, so
// a retry is not stored twice. It returns the stored version when the value
// matches, ErrVersionExists when it does not, and nothing at all when the ID
// is new or absent.
//
// Both writes that take a client request token need this: the SDKs fill one in
// for PutSecretValue and UpdateSecret alike, so an SDK-level retry of either
// arrives carrying the version ID of the call before it.
func storedVersion(
	rec *record,
	versionID string,
	payload contracts.Payload,
) (*contracts.SecretVersion, error) {
	if versionID == "" {
		return nil, nil
	}

	existing := rec.byID(versionID)
	if existing == nil {
		return nil, nil
	}
	if !existing.payload().Equal(payload) {
		return nil, fmt.Errorf("%w: version %s of %s",
			contracts.ErrVersionExists, versionID, rec.Name)
	}

	return &contracts.SecretVersion{
		SecretRef:     rec.ref(),
		VersionID:     existing.VersionID,
		VersionStages: slices.Clone(existing.Stages),
	}, nil
}

// appendVersion adds a version holding payload to rec, without storing it.
// Empty stages means AWSCURRENT, and an empty versionID is generated.
func (s *Service) appendVersion(
	rec *record,
	versionID string,
	payload contracts.Payload,
	stages []string,
) (*contracts.SecretVersion, error) {
	if versionID == "" {
		var err error
		if versionID, err = newVersionID(); err != nil {
			return nil, err
		}
	}
	if len(stages) == 0 {
		stages = []string{contracts.StageCurrent}
	}

	rec.addVersion(recordVersion{
		VersionID:    versionID,
		CreatedDate:  s.now().UTC(),
		SecretString: payload.String,
		SecretBinary: payload.Binary,
	}, stages)

	added := rec.byID(versionID)
	return &contracts.SecretVersion{
		SecretRef:     rec.ref(),
		VersionID:     versionID,
		VersionStages: slices.Clone(added.Stages),
	}, nil
}

// UpdateSecretVersionStage moves a staging label between versions: with a
// destination it attaches the label, and with only a source it detaches it.
// Moving AWSCURRENT also moves AWSPREVIOUS onto the version it came from.
//
// The checks follow the RemoveFromVersionId contract: a label already held by
// another version can only be moved by a request that names the version it
// comes off, and that version must be the one holding it.
func (s *Service) UpdateSecretVersionStage(
	_ context.Context,
	in contracts.UpdateSecretVersionStageInput,
) (*contracts.SecretRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.resolveLive(in.SecretID)
	if err != nil {
		return nil, err
	}

	if err = checkStageMove(rec, in); err != nil {
		return nil, err
	}

	if in.MoveTo != "" {
		rec.moveStage(in.MoveTo, in.VersionStage)
	} else {
		rec.detachStage(in.VersionStage)
	}

	rec.LastChangedDate = s.now().UTC()
	if err = s.write(rec); err != nil {
		return nil, err
	}

	ref := rec.ref()
	return &ref, nil
}

// checkStageMove rejects a label move Secrets Manager would not make.
//
// The one rule not taken from the API reference is the last: removing
// AWSCURRENT without moving it elsewhere is refused. The SDK documentation
// says only that a version losing its last label is deprecated, and says
// nothing either way about a secret left with no current version, so this is
// stricter than anything verifiable rather than a documented behavior. A
// secret in that state answers no ordinary read, and a client cannot put it
// right without a version ID it has no way to know, which is worse than an
// error at the call that would have caused it.
func checkStageMove(rec *record, in contracts.UpdateSecretVersionStageInput) error {
	held := rec.byStage(in.VersionStage)

	if in.RemoveFrom != "" {
		from := rec.byID(in.RemoveFrom)
		if from == nil {
			return fmt.Errorf("%w: version %s of %s",
				contracts.ErrVersionNotFound, in.RemoveFrom, rec.Name)
		}
		if !slices.Contains(from.Stages, in.VersionStage) {
			return fmt.Errorf("%w: %s is not on version %s of %s",
				contracts.ErrStageMismatch, in.VersionStage, in.RemoveFrom, rec.Name)
		}
	}

	if in.MoveTo != "" {
		if rec.byID(in.MoveTo) == nil {
			return fmt.Errorf("%w: version %s of %s",
				contracts.ErrVersionNotFound, in.MoveTo, rec.Name)
		}
		if in.RemoveFrom == "" && held != nil && held.VersionID != in.MoveTo {
			return fmt.Errorf("%w: %s is on version %s of %s",
				contracts.ErrStageAttached, in.VersionStage, held.VersionID, rec.Name)
		}
		return nil
	}

	if in.VersionStage == contracts.StageCurrent {
		return fmt.Errorf("%w: %s", contracts.ErrCurrentStageRequired, rec.Name)
	}
	return nil
}

// resolveLive loads a secret and refuses one that is scheduled for deletion,
// which is what every operation but DescribeSecret and RestoreSecret does.
func (s *Service) resolveLive(secretID string) (*record, error) {
	rec, err := s.resolve(secretID)
	if err != nil {
		return nil, err
	}
	if rec.deleted() {
		return nil, fmt.Errorf("%w: %s", contracts.ErrSecretDeleted, rec.Name)
	}
	return rec, nil
}

func errorIsNotFound(err error) bool {
	return errors.Is(err, contracts.ErrSecretNotFound)
}

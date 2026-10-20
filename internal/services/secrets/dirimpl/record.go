package dirimpl

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"tule.dev/secret-store/internal/contracts"
)

// record is one secret as it is stored: its metadata and every version of its
// value, oldest version first.
type record struct {
	CreatedDate      time.Time       `json:"createdDate"`
	LastChangedDate  time.Time       `json:"lastChangedDate"`
	LastAccessedDate time.Time       `json:"lastAccessedDate,omitzero"`
	DeletedDate      time.Time       `json:"deletedDate,omitzero"`
	Name             string          `json:"name"`
	ARN              string          `json:"arn"`
	Description      string          `json:"description,omitempty"`
	KmsKeyID         string          `json:"kmsKeyId,omitempty"`
	Tags             []contracts.Tag `json:"tags,omitempty"`
	Versions         []recordVersion `json:"versions"`
}

// recordVersion is one version of a secret's value. Exactly one of
// SecretString and SecretBinary is set, as Secrets Manager reports back
// whichever kind was written.
type recordVersion struct {
	CreatedDate  time.Time `json:"createdDate"`
	SecretString *string   `json:"secretString,omitempty"`
	VersionID    string    `json:"versionId"`
	SecretBinary []byte    `json:"secretBinary,omitempty"`
	Stages       []string  `json:"stages,omitempty"`
}

func (r *record) ref() contracts.SecretRef {
	return contracts.SecretRef{ARN: r.ARN, Name: r.Name}
}

// deleted reports whether the secret is scheduled for deletion.
func (r *record) deleted() bool {
	return !r.DeletedDate.IsZero()
}

// byID returns the version with the given ID, or nil.
func (r *record) byID(versionID string) *recordVersion {
	for i := range r.Versions {
		if r.Versions[i].VersionID == versionID {
			return &r.Versions[i]
		}
	}
	return nil
}

// byStage returns the version carrying the given staging label, or nil.
func (r *record) byStage(stage string) *recordVersion {
	for i := range r.Versions {
		if slices.Contains(r.Versions[i].Stages, stage) {
			return &r.Versions[i]
		}
	}
	return nil
}

// detachStage removes a staging label from whichever version holds it.
func (r *record) detachStage(stage string) {
	for i := range r.Versions {
		r.Versions[i].Stages = slices.DeleteFunc(r.Versions[i].Stages,
			func(s string) bool { return s == stage })
	}
}

// attachStage moves a staging label onto one version.
func (r *record) attachStage(versionID, stage string) {
	r.detachStage(stage)
	if v := r.byID(versionID); v != nil && !slices.Contains(v.Stages, stage) {
		v.Stages = append(v.Stages, stage)
	}
}

// moveStage moves a staging label onto one version, following the one rule
// Secrets Manager applies on top of a plain move: "Whenever you move
// AWSCURRENT, Secrets Manager automatically moves the label AWSPREVIOUS to the
// version that AWSCURRENT was removed from", so the value just replaced stays
// reachable without its version ID.
//
// Every write that attaches a label goes through here, so storing a new
// current version and promoting an existing one behave the same way.
func (r *record) moveStage(versionID, stage string) {
	if stage == contracts.StageCurrent {
		if held := r.byStage(stage); held != nil && held.VersionID != versionID {
			replaced := held.VersionID
			r.attachStage(versionID, stage)
			r.attachStage(replaced, contracts.StagePrevious)
			return
		}
	}
	r.attachStage(versionID, stage)
}

// addVersion appends a version and gives it stages, moving each label off
// whichever version holds it.
func (r *record) addVersion(v recordVersion, stages []string) {
	v.Stages = nil
	r.Versions = append(r.Versions, v)

	for _, stage := range stages {
		r.moveStage(v.VersionID, stage)
	}
}

// versionStages reports a secret's versions and their staging labels.
func (r *record) versionStages() map[string][]string {
	stages := make(map[string][]string, len(r.Versions))
	for _, v := range r.Versions {
		if len(v.Stages) > 0 {
			stages[v.VersionID] = slices.Clone(v.Stages)
		}
	}
	return stages
}

func (r *record) detail() contracts.SecretDetail {
	return contracts.SecretDetail{
		SecretRef:        r.ref(),
		Description:      r.Description,
		KmsKeyID:         r.KmsKeyID,
		Tags:             slices.Clone(r.Tags),
		CreatedDate:      r.CreatedDate,
		LastChangedDate:  r.LastChangedDate,
		LastAccessedDate: r.LastAccessedDate,
		DeletedDate:      r.DeletedDate,
		VersionStages:    r.versionStages(),
	}
}

// payload returns a version's value in contract terms.
func (v *recordVersion) payload() contracts.Payload {
	return contracts.Payload{String: v.SecretString, Binary: v.SecretBinary}
}

// read loads the secret stored under name.
func (s *Service) read(name string) (*record, error) {
	data, err := s.root.ReadFile(fileName(name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", contracts.ErrSecretNotFound, name)
		}
		return nil, fmt.Errorf("failed to read secret %s: %w", name, err)
	}

	var rec record
	if err = json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("failed to decode secret %s: %w", name, err)
	}
	return &rec, nil
}

// write stores rec, replacing the file in one rename so a reader never sees a
// half-written secret.
func (s *Service) write(rec *record) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to encode secret %s: %w", rec.Name, err)
	}

	final := fileName(rec.Name)
	tmp := final + ".tmp"
	if err = s.root.WriteFile(tmp, data, filePerm); err != nil {
		return fmt.Errorf("failed to write secret %s: %w", rec.Name, err)
	}
	if err = s.root.Rename(tmp, final); err != nil {
		return errors.Join(
			fmt.Errorf("failed to store secret %s: %w", rec.Name, err),
			s.root.Remove(tmp),
		)
	}
	return nil
}

// remove deletes a secret's file.
func (s *Service) remove(name string) error {
	if err := s.root.Remove(fileName(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to remove secret %s: %w", name, err)
	}
	return nil
}

// resolve loads the secret a request's identifier names, which may be its
// name, its full ARN or its ARN without the random suffix.
func (s *Service) resolve(secretID string) (*record, error) {
	names := candidateNames(secretID)
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: %s", contracts.ErrSecretNotFound, secretID)
	}

	for _, name := range names {
		rec, err := s.read(name)
		switch {
		case err == nil && (!strings.HasPrefix(secretID, arnPrefix) || matchesARN(rec, secretID)):
			return rec, nil
		case err != nil && !errors.Is(err, contracts.ErrSecretNotFound):
			return nil, err
		}
	}
	return nil, fmt.Errorf("%w: %s", contracts.ErrSecretNotFound, secretID)
}

// matchesARN reports whether an ARN identifies rec: either its ARN exactly, or
// the same ARN without the random suffix, which Secrets Manager accepts as a
// partial ARN.
func matchesARN(rec *record, arn string) bool {
	if rec.ARN == arn {
		return true
	}
	trimmed, ok := trimARNSuffix(rec.ARN)
	return ok && trimmed == arn
}

// all loads every stored secret, in name order.
func (s *Service) all() ([]*record, error) {
	entries, err := fs.ReadDir(s.root.FS(), secretsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	recs := make([]*record, 0, len(entries))
	for _, entry := range entries {
		// Skip the temporary file of a write interrupted by a crash.
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		data, rErr := s.root.ReadFile(secretsDir + "/" + entry.Name())
		if rErr != nil {
			return nil, fmt.Errorf("failed to read %s: %w", entry.Name(), rErr)
		}
		var rec record
		if uErr := json.Unmarshal(data, &rec); uErr != nil {
			return nil, fmt.Errorf("failed to decode %s: %w", entry.Name(), uErr)
		}
		recs = append(recs, &rec)
	}

	slices.SortFunc(recs, func(a, b *record) int { return strings.Compare(a.Name, b.Name) })
	return recs, nil
}

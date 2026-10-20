// Package contracts defines the secret store interface the HTTP modules
// depend on, with its input and output types and sentinel errors.
package contracts

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrSecretNotFound is returned when no secret matches the given identifier.
	ErrSecretNotFound = errors.New("secrets: secret not found")

	// ErrSecretExists is returned by CreateSecret when the name is taken.
	ErrSecretExists = errors.New("secrets: secret already exists")

	// ErrVersionExists is returned when a version ID is reused for a different
	// value, which would make the client request token ambiguous.
	ErrVersionExists = errors.New("secrets: secret version already exists")

	// ErrVersionNotFound is returned when no version matches the requested
	// version ID or staging label.
	ErrVersionNotFound = errors.New("secrets: secret version not found")

	// ErrSecretDeleted is returned for operations on a secret that is
	// scheduled for deletion, which only RestoreSecret and DescribeSecret
	// accept.
	ErrSecretDeleted = errors.New("secrets: secret is scheduled for deletion")

	// ErrSecretNotDeleted is returned by RestoreSecret for a secret that is
	// not scheduled for deletion.
	ErrSecretNotDeleted = errors.New("secrets: secret is not scheduled for deletion")

	// ErrInvalidName is returned when a secret name breaks the Secrets Manager
	// naming rules.
	ErrInvalidName = errors.New("secrets: invalid secret name")

	// ErrInvalidValue is returned when a write carries neither a string nor a
	// binary value, or both.
	ErrInvalidValue = errors.New("secrets: exactly one of the string and binary value is required")

	// ErrStageMismatch is returned when a staging label is moved off a version
	// that does not hold it.
	ErrStageMismatch = errors.New("secrets: staging label is not on that version")

	// ErrStageAttached is returned when a staging label is moved onto a
	// version while another version holds it, without naming the version it
	// should come off.
	ErrStageAttached = errors.New("secrets: staging label is attached to another version")

	// ErrCurrentStageRequired is returned when a request would leave a secret
	// with no AWSCURRENT version, which no read could then resolve.
	ErrCurrentStageRequired = errors.New("secrets: a secret must keep an AWSCURRENT version")

	// ErrValueTooLarge is returned for a value above MaxValueSize.
	ErrValueTooLarge = errors.New("secrets: secret value is too large")

	// ErrInvalidToken is returned for a pagination token the store did not
	// issue.
	ErrInvalidToken = errors.New("secrets: invalid pagination token")
)

// The staging labels Secrets Manager manages on behalf of the caller.
// AWSCURRENT marks the version reads return by default and AWSPREVIOUS the one
// it replaced. AWSPENDING is only ever set by an explicit request, since
// nothing here rotates secrets.
const (
	StageCurrent  = "AWSCURRENT"
	StagePrevious = "AWSPREVIOUS"
	StagePending  = "AWSPENDING"
)

// MaxValueSize is the largest value Secrets Manager stores for one secret, 64
// KiB. It is enforced so a value that is accepted here is accepted on AWS too.
const MaxValueSize = 64 << 10

// DefaultRecoveryWindow is the deletion delay DeleteSecret applies when the
// request does not ask for another one.
const DefaultRecoveryWindow = 30 * 24 * time.Hour

// SecretsProvider is the secret store the Secrets Manager API is served from:
// the secret lifecycle, the versions of a secret's value, the staging labels
// that select them, and tags.
type SecretsProvider interface {
	CreateSecret(ctx context.Context, in CreateSecretInput) (*SecretVersion, error)
	GetSecretValue(ctx context.Context, in GetSecretValueInput) (*SecretValue, error)
	PutSecretValue(ctx context.Context, in PutSecretValueInput) (*SecretVersion, error)
	UpdateSecret(ctx context.Context, in UpdateSecretInput) (*SecretVersion, error)
	DescribeSecret(ctx context.Context, secretID string) (*SecretDetail, error)
	DeleteSecret(ctx context.Context, in DeleteSecretInput) (*DeletedSecret, error)
	RestoreSecret(ctx context.Context, secretID string) (*SecretRef, error)
	ListSecrets(ctx context.Context, in ListSecretsInput) (*ListSecretsOutput, error)
	ListSecretVersions(
		ctx context.Context,
		in ListSecretVersionsInput,
	) (*ListSecretVersionsOutput, error)
	UpdateSecretVersionStage(
		ctx context.Context,
		in UpdateSecretVersionStageInput,
	) (*SecretRef, error)
	TagSecret(ctx context.Context, secretID string, tags []Tag) (*SecretRef, error)
	UntagSecret(ctx context.Context, secretID string, keys []string) (*SecretRef, error)
}

// Payload is one version's value. Secrets Manager stores either a string or
// binary, and reads report back whichever was written, so the two are kept
// apart rather than collapsed into bytes.
type Payload struct {
	String *string
	Binary []byte
}

// IsZero reports whether the payload carries no value at all.
func (p Payload) IsZero() bool {
	return p.String == nil && p.Binary == nil
}

// Valid reports whether the payload carries exactly one of the two values.
func (p Payload) Valid() bool {
	return (p.String == nil) != (p.Binary == nil)
}

// Size returns the length of the value in bytes.
func (p Payload) Size() int {
	if p.String != nil {
		return len(*p.String)
	}
	return len(p.Binary)
}

// Equal reports whether p holds the same value, of the same kind, as other.
func (p Payload) Equal(other Payload) bool {
	switch {
	case p.String != nil && other.String != nil:
		return *p.String == *other.String
	case p.Binary != nil && other.Binary != nil:
		return string(p.Binary) == string(other.Binary)
	default:
		return p.IsZero() && other.IsZero()
	}
}

// Tag is one of a secret's tags.
type Tag struct {
	Key   string
	Value string
}

// SecretRef names a secret by both of its identifiers.
type SecretRef struct {
	ARN  string
	Name string
}

// SecretVersion names a secret and the version a write produced, with the
// staging labels that version ended up holding.
type SecretVersion struct {
	SecretRef
	VersionID     string
	VersionStages []string
}

// SecretValue is one version of a secret's value.
type SecretValue struct {
	CreatedDate time.Time
	SecretRef
	VersionID     string
	VersionStages []string
	Payload       Payload
}

// SecretDetail describes a secret without exposing any of its values.
// DeletedDate is zero unless the secret is scheduled for deletion. KmsKeyID is
// what the client asked to encrypt the secret with, which nothing here acts
// on; it is reported back so a client sees its own setting.
type SecretDetail struct {
	CreatedDate      time.Time
	LastChangedDate  time.Time
	LastAccessedDate time.Time
	DeletedDate      time.Time
	VersionStages    map[string][]string
	SecretRef
	Description string
	KmsKeyID    string
	Tags        []Tag
}

// DeletedSecret is the outcome of a DeleteSecret call. DeletionDate is zero
// when the secret was deleted outright.
type DeletedSecret struct {
	DeletionDate time.Time
	SecretRef
}

// CreateSecretInput creates a secret holding Payload as its first version.
// VersionID, from the request's client request token, names that version; an
// empty one is generated.
type CreateSecretInput struct {
	Name        string
	Description string
	KmsKeyID    string
	VersionID   string
	Payload     Payload
	Tags        []Tag
}

// GetSecretValueInput selects one version of a secret's value. VersionID wins
// over VersionStage, and an empty VersionStage means StageCurrent.
type GetSecretValueInput struct {
	SecretID     string
	VersionID    string
	VersionStage string
}

// PutSecretValueInput stores a new version of a secret's value. VersionID,
// from the request's client request token, names it; an empty one is
// generated. An empty VersionStages means StageCurrent, which also moves
// StagePrevious onto the version being replaced.
type PutSecretValueInput struct {
	SecretID      string
	VersionID     string
	Payload       Payload
	VersionStages []string
}

// UpdateSecretInput changes a secret's description or KMS key, and stores a
// new current version when Payload carries one. A nil Description or KmsKeyID
// leaves that field as it is.
type UpdateSecretInput struct {
	Description *string
	KmsKeyID    *string
	SecretID    string
	VersionID   string
	Payload     Payload
}

// DeleteSecretInput schedules a secret for deletion after RecoveryWindow, or
// deletes it outright when Force is set. A zero RecoveryWindow means
// DefaultRecoveryWindow.
type DeleteSecretInput struct {
	SecretID       string
	RecoveryWindow time.Duration
	Force          bool
}

// ListSecretsInput pages through the secrets in name order. MaxResults of
// zero means the store's own page size, and secrets scheduled for deletion
// are left out unless IncludeDeleted is set.
type ListSecretsInput struct {
	NextToken      string
	MaxResults     int
	IncludeDeleted bool
}

// ListSecretsOutput is one page of a secret listing. NextToken is empty on the
// last page.
type ListSecretsOutput struct {
	NextToken string
	Secrets   []SecretDetail
}

// ListSecretVersionsInput pages through one secret's versions, newest first.
// Versions holding no staging label are left out unless IncludeDeprecated is
// set.
type ListSecretVersionsInput struct {
	SecretID          string
	NextToken         string
	MaxResults        int
	IncludeDeprecated bool
}

// ListSecretVersionsOutput is one page of a version listing. NextToken is
// empty on the last page.
type ListSecretVersionsOutput struct {
	NextToken string
	SecretRef
	Versions []VersionInfo
}

// VersionInfo describes one version of a secret without its value.
type VersionInfo struct {
	CreatedDate   time.Time
	VersionID     string
	VersionStages []string
}

// UpdateSecretVersionStageInput moves VersionStage between two versions.
// MoveTo alone attaches the label, RemoveFrom alone detaches it, and both
// together require the label to currently sit on RemoveFrom.
type UpdateSecretVersionStageInput struct {
	SecretID     string
	VersionStage string
	MoveTo       string
	RemoveFrom   string
}

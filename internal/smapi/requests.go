package smapi

// The request bodies this service reads. Field names and types follow the
// Secrets Manager API model: a value the caller may legitimately send as empty
// is a pointer, so an absent field can be told from an empty one.

// CreateSecretRequest is the body of CreateSecret.
type CreateSecretRequest struct {
	Name               string  `json:"Name"`
	Description        string  `json:"Description"`
	KmsKeyID           string  `json:"KmsKeyId"`
	ClientRequestToken string  `json:"ClientRequestToken"`
	SecretString       *string `json:"SecretString"`
	SecretBinary       []byte  `json:"SecretBinary"`
	Tags               []Tag   `json:"Tags"`
}

// GetSecretValueRequest is the body of GetSecretValue.
type GetSecretValueRequest struct {
	SecretID     string `json:"SecretId"`
	VersionID    string `json:"VersionId"`
	VersionStage string `json:"VersionStage"`
}

// PutSecretValueRequest is the body of PutSecretValue.
type PutSecretValueRequest struct {
	SecretID           string   `json:"SecretId"`
	ClientRequestToken string   `json:"ClientRequestToken"`
	SecretString       *string  `json:"SecretString"`
	SecretBinary       []byte   `json:"SecretBinary"`
	VersionStages      []string `json:"VersionStages"`
}

// UpdateSecretRequest is the body of UpdateSecret.
type UpdateSecretRequest struct {
	SecretID           string  `json:"SecretId"`
	ClientRequestToken string  `json:"ClientRequestToken"`
	Description        *string `json:"Description"`
	KmsKeyID           *string `json:"KmsKeyId"`
	SecretString       *string `json:"SecretString"`
	SecretBinary       []byte  `json:"SecretBinary"`
}

// SecretIDRequest is the body of the operations that take nothing but a secret
// identifier: DescribeSecret and RestoreSecret.
type SecretIDRequest struct {
	SecretID string `json:"SecretId"`
}

// DeleteSecretRequest is the body of DeleteSecret.
type DeleteSecretRequest struct {
	RecoveryWindowInDays       *int64 `json:"RecoveryWindowInDays"`
	SecretID                   string `json:"SecretId"`
	ForceDeleteWithoutRecovery bool   `json:"ForceDeleteWithoutRecovery"`
}

// ListSecretsRequest is the body of ListSecrets.
type ListSecretsRequest struct {
	NextToken              string   `json:"NextToken"`
	SortBy                 string   `json:"SortBy"`
	SortOrder              string   `json:"SortOrder"`
	Filters                []Filter `json:"Filters"`
	MaxResults             int      `json:"MaxResults"`
	IncludePlannedDeletion bool     `json:"IncludePlannedDeletion"`
}

// ListSecretVersionIDsRequest is the body of ListSecretVersionIds.
type ListSecretVersionIDsRequest struct {
	SecretID          string `json:"SecretId"`
	NextToken         string `json:"NextToken"`
	MaxResults        int    `json:"MaxResults"`
	IncludeDeprecated bool   `json:"IncludeDeprecated"`
}

// UpdateSecretVersionStageRequest is the body of UpdateSecretVersionStage.
type UpdateSecretVersionStageRequest struct {
	SecretID            string `json:"SecretId"`
	VersionStage        string `json:"VersionStage"`
	MoveToVersionID     string `json:"MoveToVersionId"`
	RemoveFromVersionID string `json:"RemoveFromVersionId"`
}

// TagResourceRequest is the body of TagResource.
type TagResourceRequest struct {
	SecretID string `json:"SecretId"`
	Tags     []Tag  `json:"Tags"`
}

// UntagResourceRequest is the body of UntagResource.
type UntagResourceRequest struct {
	SecretID string   `json:"SecretId"`
	TagKeys  []string `json:"TagKeys"`
}

// BatchGetSecretValueRequest is the body of BatchGetSecretValue.
type BatchGetSecretValueRequest struct {
	NextToken    string   `json:"NextToken"`
	SecretIDList []string `json:"SecretIdList"`
	Filters      []Filter `json:"Filters"`
	MaxResults   int      `json:"MaxResults"`
}

// Filter is one of the filters the list operations accept. None of them are
// served, so a request carrying one is rejected rather than quietly answered
// with everything.
type Filter struct {
	Key    string   `json:"Key"`
	Values []string `json:"Values"`
}

// Tag is one of a secret's tags.
type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

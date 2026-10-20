package smapi

// The response bodies this service writes. Every field the Secrets Manager
// model marks optional is omitted when empty, so a response carries only what
// this service actually knows.

// SecretRefResponse is the body of the operations that answer with nothing but
// the secret's two identifiers: RestoreSecret and UpdateSecretVersionStage.
type SecretRefResponse struct {
	ARN  string `json:"ARN,omitempty"`
	Name string `json:"Name,omitempty"`
}

// CreateSecretResponse is the body of CreateSecret and UpdateSecret.
type CreateSecretResponse struct {
	SecretRefResponse
	VersionID string `json:"VersionId,omitempty"`
}

// GetSecretValueResponse is the body of GetSecretValue.
type GetSecretValueResponse struct {
	CreatedDate  *Timestamp `json:"CreatedDate,omitempty"`
	SecretString *string    `json:"SecretString,omitempty"`
	SecretRefResponse
	VersionID     string   `json:"VersionId,omitempty"`
	SecretBinary  []byte   `json:"SecretBinary,omitempty"`
	VersionStages []string `json:"VersionStages,omitempty"`
}

// PutSecretValueResponse is the body of PutSecretValue.
type PutSecretValueResponse struct {
	SecretRefResponse
	VersionID     string   `json:"VersionId,omitempty"`
	VersionStages []string `json:"VersionStages,omitempty"`
}

// DeleteSecretResponse is the body of DeleteSecret.
type DeleteSecretResponse struct {
	DeletionDate *Timestamp `json:"DeletionDate,omitempty"`
	SecretRefResponse
}

// DescribeSecretResponse is the body of DescribeSecret.
type DescribeSecretResponse struct {
	CreatedDate        *Timestamp          `json:"CreatedDate,omitempty"`
	LastChangedDate    *Timestamp          `json:"LastChangedDate,omitempty"`
	LastAccessedDate   *Timestamp          `json:"LastAccessedDate,omitempty"`
	DeletedDate        *Timestamp          `json:"DeletedDate,omitempty"`
	VersionIDsToStages map[string][]string `json:"VersionIdsToStages,omitempty"`
	SecretRefResponse
	Description string `json:"Description,omitempty"`
	KmsKeyID    string `json:"KmsKeyId,omitempty"`
	Tags        []Tag  `json:"Tags,omitempty"`
}

// SecretListEntry is one secret in a ListSecrets response. It is
// DescribeSecret's shape with the version map under the name the list
// operation uses for it.
type SecretListEntry struct {
	CreatedDate            *Timestamp          `json:"CreatedDate,omitempty"`
	LastChangedDate        *Timestamp          `json:"LastChangedDate,omitempty"`
	LastAccessedDate       *Timestamp          `json:"LastAccessedDate,omitempty"`
	DeletedDate            *Timestamp          `json:"DeletedDate,omitempty"`
	SecretVersionsToStages map[string][]string `json:"SecretVersionsToStages,omitempty"`
	SecretRefResponse
	Description string `json:"Description,omitempty"`
	KmsKeyID    string `json:"KmsKeyId,omitempty"`
	Tags        []Tag  `json:"Tags,omitempty"`
}

// ListSecretsResponse is the body of ListSecrets.
type ListSecretsResponse struct {
	NextToken  string            `json:"NextToken,omitempty"`
	SecretList []SecretListEntry `json:"SecretList"`
}

// VersionsListEntry is one version in a ListSecretVersionIds response.
type VersionsListEntry struct {
	CreatedDate   *Timestamp `json:"CreatedDate,omitempty"`
	VersionID     string     `json:"VersionId,omitempty"`
	VersionStages []string   `json:"VersionStages,omitempty"`
}

// ListSecretVersionIDsResponse is the body of ListSecretVersionIds.
type ListSecretVersionIDsResponse struct {
	NextToken string `json:"NextToken,omitempty"`
	SecretRefResponse
	Versions []VersionsListEntry `json:"Versions"`
}

// BatchSecretValue is one secret's value in a BatchGetSecretValue response.
type BatchSecretValue struct {
	CreatedDate  *Timestamp `json:"CreatedDate,omitempty"`
	SecretString *string    `json:"SecretString,omitempty"`
	SecretRefResponse
	VersionID     string   `json:"VersionId,omitempty"`
	SecretBinary  []byte   `json:"SecretBinary,omitempty"`
	VersionStages []string `json:"VersionStages,omitempty"`
}

// BatchError reports one secret a BatchGetSecretValue call could not read.
type BatchError struct {
	SecretID  string `json:"SecretId,omitempty"`
	ErrorCode string `json:"ErrorCode,omitempty"`
	Message   string `json:"Message,omitempty"`
}

// BatchGetSecretValueResponse is the body of BatchGetSecretValue.
type BatchGetSecretValueResponse struct {
	NextToken    string             `json:"NextToken,omitempty"`
	SecretValues []BatchSecretValue `json:"SecretValues"`
	Errors       []BatchError       `json:"Errors,omitempty"`
}

// EmptyResponse is the body of the operations that answer with nothing:
// TagResource and UntagResource.
type EmptyResponse struct{}

package authz

// This file is the mapping from every Secrets Manager operation this service
// routes to the IAM actions it is authorized as, the resource each action is
// on, and the service condition keys the service supplies for it. It is taken
// from AWS's Service Authorization Reference for Secrets Manager
// (https://servicereference.us-east-1.amazonaws.com/v1/secretsmanager/secretsmanager.json,
// copied to testdata/secretsmanager.json, and
// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awssecretsmanager.html).
// The operation's AuthorizedActions there name the actions; the action's
// Resources name its resource type, or none for "*"; its ActionConditionKeys
// name the keys it may be given. mapping_test.go checks every entry against
// that copy.

// Resource is what an action is evaluated on.
type Resource int

const (
	// AllResources is "*": the reference lists no resource type for the
	// action.
	AllResources Resource = iota + 1
	// Secret is the secret the request names,
	// arn:aws:secretsmanager:<region>:<account>:secret:<name>-<6 characters>.
	// A secret that does not exist is evaluated as the ARN the request gave,
	// or for a name as arn:aws:secretsmanager:<region>:<account>:secret:<name>.
	Secret
	// NewSecret is the ARN the secret CreateSecret creates will have, random
	// suffix included, which is minted before the request is evaluated.
	NewSecret
)

// Check is one authorization an operation needs.
type Check struct {
	// Action is the IAM action, as the reference names it.
	Action string
	// When says when the check applies, empty for every request.
	When string
	// Keys are the service condition keys supplied with the action, as the
	// reference names them; a tag key is written with the reference's
	// placeholder (aws:ResourceTag/${TagKey}, secretsmanager:ResourceTag/tag-key).
	// The global aws: keys of every request are supplied besides these.
	Keys     []string
	Resource Resource
}

// The keys the reference lists for every action on a secret, which the
// service supplies from the secret: its tags, its ARN and its region, which
// is always its primary region since nothing here replicates.
var secretKeys = []string{
	"aws:ResourceTag/${TagKey}",
	"secretsmanager:ResourceTag/tag-key",
	"secretsmanager:SecretId",
	"secretsmanager:SecretPrimaryRegion",
}

func withSecretKeys(keys ...string) []string {
	return append(append([]string(nil), secretKeys...), keys...)
}

// Operations maps every routed operation to the checks it needs, in the order
// they are made. The first check is the operation's own action.
var Operations = map[string][]Check{
	"BatchGetSecretValue": {
		{Action: "secretsmanager:BatchGetSecretValue", Resource: AllResources},
		// "you must have secretsmanager:GetSecretValue for each secret"
		// (BatchGetSecretValue, API reference). A secret it is denied is
		// reported in the response's Errors as AccessDeniedException.
		// secretsmanager:ListSecrets is only needed with Filters, which
		// this service refuses.
		{
			Action: "secretsmanager:GetSecretValue", Resource: Secret,
			When: "for each secret in SecretIdList", Keys: withSecretKeys(),
		},
	},
	"CreateSecret": {
		{
			Action: "secretsmanager:CreateSecret", Resource: NewSecret,
			Keys: []string{
				"secretsmanager:Name", "secretsmanager:Description",
				"secretsmanager:KmsKeyId", "aws:RequestTag/${TagKey}", "aws:TagKeys",
			},
		},
		// "If you include tags in the secret, you also need
		// secretsmanager:TagResource." (CreateSecret, API reference.)
		{
			Action: "secretsmanager:TagResource", Resource: NewSecret,
			When: "when the request has Tags",
			Keys: []string{"aws:RequestTag/${TagKey}", "aws:TagKeys", "secretsmanager:SecretId"},
		},
	},
	"DeleteSecret": {{
		Action: "secretsmanager:DeleteSecret", Resource: Secret,
		Keys: withSecretKeys(
			"secretsmanager:ForceDeleteWithoutRecovery", "secretsmanager:RecoveryWindowInDays"),
	}},
	"DeleteResourcePolicy": {{
		Action: "secretsmanager:DeleteResourcePolicy", Resource: Secret,
		Keys: withSecretKeys("secretsmanager:PolicyName"),
	}},
	"DescribeSecret": {{
		Action: "secretsmanager:DescribeSecret", Resource: Secret, Keys: withSecretKeys(),
	}},
	// The reference gives GetRandomPassword no resource type and no
	// condition keys: it acts on no secret.
	"GetRandomPassword": {{Action: "secretsmanager:GetRandomPassword", Resource: AllResources}},
	"GetResourcePolicy": {{
		Action: "secretsmanager:GetResourcePolicy", Resource: Secret,
		Keys: withSecretKeys("secretsmanager:PolicyName"),
	}},
	"GetSecretValue": {{
		Action: "secretsmanager:GetSecretValue", Resource: Secret,
		Keys: withSecretKeys("secretsmanager:VersionId", "secretsmanager:VersionStage"),
	}},
	"ListSecretVersionIds": {{
		Action: "secretsmanager:ListSecretVersionIds", Resource: Secret, Keys: withSecretKeys(),
	}},
	"ListSecrets": {{Action: "secretsmanager:ListSecrets", Resource: AllResources}},
	"PutResourcePolicy": {{
		Action: "secretsmanager:PutResourcePolicy", Resource: Secret,
		Keys: withSecretKeys("secretsmanager:BlockPublicPolicy", "secretsmanager:PolicyName"),
	}},
	"PutSecretValue": {{
		Action: "secretsmanager:PutSecretValue", Resource: Secret, Keys: withSecretKeys(),
	}},
	"RestoreSecret": {{
		Action: "secretsmanager:RestoreSecret", Resource: Secret, Keys: withSecretKeys(),
	}},
	"TagResource": {{
		Action: "secretsmanager:TagResource", Resource: Secret,
		Keys: withSecretKeys("aws:RequestTag/${TagKey}", "aws:TagKeys"),
	}},
	"UntagResource": {{
		Action: "secretsmanager:UntagResource", Resource: Secret,
		Keys: withSecretKeys("aws:TagKeys"),
	}},
	"UpdateSecret": {{
		Action: "secretsmanager:UpdateSecret", Resource: Secret,
		Keys: withSecretKeys("secretsmanager:Description", "secretsmanager:KmsKeyId"),
	}},
	"UpdateSecretVersionStage": {{
		Action: "secretsmanager:UpdateSecretVersionStage", Resource: Secret,
		Keys: withSecretKeys("secretsmanager:VersionStage"),
	}},
	// "Required permissions: secretsmanager:ValidateResourcePolicy and
	// secretsmanager:PutResourcePolicy" (ValidateResourcePolicy, API
	// reference). Without a SecretId both are evaluated on "*", as actions on
	// no secret of the store's.
	"ValidateResourcePolicy": {
		{
			Action: "secretsmanager:ValidateResourcePolicy", Resource: Secret,
			Keys: withSecretKeys(),
		},
		{
			Action: "secretsmanager:PutResourcePolicy", Resource: Secret,
			Keys: withSecretKeys(),
		},
	},
}

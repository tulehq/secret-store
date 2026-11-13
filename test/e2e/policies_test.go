//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// statement is one statement of a policy document the tests write.
type statement struct {
	Condition map[string]map[string]any `json:"Condition,omitempty"`
	Principal map[string]any            `json:"Principal,omitempty"`
	Effect    string                    `json:"Effect"`
	Action    []string                  `json:"Action"`
	Resource  []string                  `json:"Resource,omitempty"`
}

func policyDoc(statements ...statement) string {
	b, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// allowDoc is a policy allowing actions on resource.
func allowDoc(actions []string, resource string) string {
	return policyDoc(statement{Effect: "Allow", Action: actions, Resource: []string{resource}})
}

// putDevPolicy gives the user "dev" the inline policy doc, replacing the one
// it had.
func putDevPolicy(t *testing.T, ic *iam.Client, doc string) {
	t.Helper()
	_, err := ic.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{
		UserName:       aws.String("dev"),
		PolicyName:     aws.String("secrets"),
		PolicyDocument: aws.String(doc),
	})
	requireNoErr(t, err, "put a policy on dev")
}

// secretPattern is the ARN pattern of the secret name: its ARN with any
// random suffix, as AWS documents granting a secret by name.
func secretPattern(name string) string {
	return "arn:aws:secretsmanager:us-east-1:000000000000:secret:" + name + "-??????"
}

// requireDenied fails unless err is Secrets Manager's AccessDeniedException,
// a 400, with message msg.
func requireDenied(t *testing.T, err error, msg string) {
	t.Helper()
	requireCode(t, err, "AccessDeniedException")
	requireResponse(t, err, http.StatusBadRequest)
	var apiErr smithy.APIError
	errors.As(err, &apiErr) // requireCode has checked it is one
	requireEqual(t, apiErr.ErrorMessage(), msg, "error message")
}

func implicitDeny(principal, action, resource string) string {
	return "User: " + principal + " is not authorized to perform: " + action +
		" on resource: " + resource + " because no identity-based policy allows the " +
		action + " action"
}

func resourceDeny(principal, action, resource string) string {
	return "User: " + principal + " is not authorized to perform: " + action +
		" on resource: " + resource + " because no resource-based policy allows the " +
		action + " action"
}

func explicitDeny(principal, action, resource string) string {
	return "User: " + principal + " is not authorized to perform: " + action +
		" on resource: " + resource + " with an explicit deny in an identity-based policy"
}

const devARN = "arn:aws:iam::000000000000:user/dev"

// policyFixture is identity and secret-store wired together, with secrets the
// root key created and a user "dev" with a key and no policy.
type policyFixture struct {
	srv  *server
	ic   *iam.Client
	root *awssm.Client
	dev  *awssm.Client
	id   *sibling
	key  aws.Credentials
}

func newPolicyFixture(t *testing.T, secrets ...string) *policyFixture {
	t.Helper()
	id := startIdentity(t, nil)
	srv := startWithIdentity(t, id)
	f := &policyFixture{srv: srv, id: id, ic: iamFor(id), root: smFor(srv, rootCreds())}
	for _, name := range secrets {
		createSecret(t, f.root, name, "value of "+name)
	}
	f.key = createUserKey(t, f.ic, "dev")
	f.dev = smFor(srv, f.key)
	return f
}

func describe(c *awssm.Client, id string) error {
	_, err := c.DescribeSecret(
		context.Background(),
		&awssm.DescribeSecretInput{SecretId: aws.String(id)},
	)
	return err //nolint:wrapcheck // the SDK's error is what the test checks
}

func TestAUserWithoutAPolicyIsDenied(t *testing.T) {
	f := newPolicyFixture(t, "app/one")

	err := readSecret(f.dev, "app/one")
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:GetSecretValue", "app/one"))

	// The message names the secret as the request did.
	arn := describeARN(t, f.root, "app/one")
	err = readSecret(f.dev, arn)
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:GetSecretValue", arn))

	_, err = f.dev.ListSecrets(t.Context(), &awssm.ListSecretsInput{})
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:ListSecrets", "*"))

	_, err = f.dev.CreateSecret(t.Context(), &awssm.CreateSecretInput{
		Name: aws.String("app/new"), SecretString: aws.String("v"),
	})
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:CreateSecret", "app/new"))

	// A secret that does not exist is denied the same way, so the caller
	// learns nothing of it.
	err = readSecret(f.dev, "app/missing")
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:GetSecretValue", "app/missing"))
}

func TestAPolicyAllowsExactlyItsAction(t *testing.T) {
	f := newPolicyFixture(t, "app/one")
	putDevPolicy(t, f.ic, allowDoc([]string{"secretsmanager:DescribeSecret"}, "*"))

	requireNoErr(t, describe(f.dev, "app/one"), "describe")

	err := readSecret(f.dev, "app/one")
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:GetSecretValue", "app/one"))
	_, err = f.dev.ListSecrets(t.Context(), &awssm.ListSecretsInput{})
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:ListSecrets", "*"))
	_, err = f.dev.PutSecretValue(t.Context(), &awssm.PutSecretValueInput{
		SecretId: aws.String("app/one"), SecretString: aws.String("changed"),
	})
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:PutSecretValue", "app/one"))
	_, err = f.dev.DeleteSecret(t.Context(), &awssm.DeleteSecretInput{
		SecretId: aws.String("app/one"),
	})
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:DeleteSecret", "app/one"))
	_, err = f.dev.TagResource(t.Context(), &awssm.TagResourceInput{
		SecretId: aws.String("app/one"),
		Tags:     []smtypes.Tag{{Key: aws.String("k"), Value: aws.String("v")}},
	})
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:TagResource", "app/one"))
}

func TestAResourceScopedPolicyAllowsOneSecretAndDeniesAnother(t *testing.T) {
	f := newPolicyFixture(t, "app/one", "app/two")
	putDevPolicy(t, f.ic, policyDoc(
		statement{
			Effect: "Allow", Action: []string{"secretsmanager:GetSecretValue"},
			Resource: []string{secretPattern("app/one")},
		},
		statement{
			Effect: "Allow", Action: []string{"secretsmanager:BatchGetSecretValue"},
			Resource: []string{"*"},
		},
	))

	requireEqual(t, getSecretString(t, f.dev, "app/one"), "value of app/one", "allowed read")
	err := readSecret(f.dev, "app/two")
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:GetSecretValue", "app/two"))

	// A batch is authorized per secret: the denied one is an entry error.
	out, err := f.dev.BatchGetSecretValue(t.Context(), &awssm.BatchGetSecretValueInput{
		SecretIdList: []string{"app/one", "app/two"},
	})
	requireNoErr(t, err, "batch get")
	requireEqual(t, len(out.SecretValues), 1, "values")
	requireEqual(t, aws.ToString(out.SecretValues[0].Name), "app/one", "value name")
	requireEqual(t, len(out.Errors), 1, "errors")
	requireEqual(t, aws.ToString(out.Errors[0].SecretId), "app/two", "error secret")
	requireEqual(t, aws.ToString(out.Errors[0].ErrorCode), "AccessDeniedException", "error code")
	requireEqual(t, aws.ToString(out.Errors[0].Message),
		implicitDeny(devARN, "secretsmanager:GetSecretValue", "app/two"), "error message")
}

func TestAnExplicitDenyBeatsAnAllow(t *testing.T) {
	f := newPolicyFixture(t, "app/one", "app/two")
	putDevPolicy(t, f.ic, policyDoc(
		statement{Effect: "Allow", Action: []string{"secretsmanager:*"}, Resource: []string{"*"}},
		statement{
			Effect: "Deny", Action: []string{"secretsmanager:GetSecretValue"},
			Resource: []string{secretPattern("app/two")},
		},
	))

	requireEqual(t, getSecretString(t, f.dev, "app/one"), "value of app/one", "allowed read")
	requireNoErr(t, describe(f.dev, "app/two"), "describe the denied secret")
	err := readSecret(f.dev, "app/two")
	requireDenied(t, err, explicitDeny(devARN, "secretsmanager:GetSecretValue", "app/two"))
}

func TestConditionsAreHonored(t *testing.T) {
	f := newPolicyFixture(t)
	_, err := f.root.CreateSecret(t.Context(), &awssm.CreateSecretInput{
		Name: aws.String("app/dev"), SecretString: aws.String("dev value"),
		Tags: []smtypes.Tag{{Key: aws.String("env"), Value: aws.String("dev")}},
	})
	requireNoErr(t, err, "create the dev secret")
	_, err = f.root.CreateSecret(t.Context(), &awssm.CreateSecretInput{
		Name: aws.String("app/prod"), SecretString: aws.String("prod value"),
		Tags: []smtypes.Tag{{Key: aws.String("env"), Value: aws.String("prod")}},
	})
	requireNoErr(t, err, "create the prod secret")

	putDevPolicy(t, f.ic, policyDoc(
		// Reads from this machine only, of secrets tagged env=dev.
		statement{
			Effect: "Allow", Action: []string{"secretsmanager:GetSecretValue"},
			Resource: []string{"*"},
			Condition: map[string]map[string]any{
				"IpAddress":    {"aws:SourceIp": "127.0.0.0/8"},
				"StringEquals": {"secretsmanager:ResourceTag/env": "dev"},
			},
		},
		// Writes from an address this test never uses.
		statement{
			Effect: "Allow", Action: []string{"secretsmanager:PutSecretValue"},
			Resource: []string{"*"},
			Condition: map[string]map[string]any{
				"IpAddress": {"aws:SourceIp": "203.0.113.0/24"},
			},
		},
		// Creating secrets only with a team tag, which also needs TagResource.
		statement{
			Effect:   "Allow",
			Action:   []string{"secretsmanager:CreateSecret", "secretsmanager:TagResource"},
			Resource: []string{"*"},
			Condition: map[string]map[string]any{
				"StringEquals": {"aws:RequestTag/team": "core"},
			},
		},
	))

	requireEqual(t, getSecretString(t, f.dev, "app/dev"), "dev value", "dev read")
	err = readSecret(f.dev, "app/prod")
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:GetSecretValue", "app/prod"))

	_, err = f.dev.PutSecretValue(t.Context(), &awssm.PutSecretValueInput{
		SecretId: aws.String("app/dev"), SecretString: aws.String("changed"),
	})
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:PutSecretValue", "app/dev"))

	_, err = f.dev.CreateSecret(t.Context(), &awssm.CreateSecretInput{
		Name: aws.String("app/core"), SecretString: aws.String("v"),
		Tags: []smtypes.Tag{{Key: aws.String("team"), Value: aws.String("core")}},
	})
	requireNoErr(t, err, "create with the team tag")
	_, err = f.dev.CreateSecret(t.Context(), &awssm.CreateSecretInput{
		Name: aws.String("app/other"), SecretString: aws.String("v"),
		Tags: []smtypes.Tag{{Key: aws.String("team"), Value: aws.String("other")}},
	})
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:CreateSecret", "app/other"))
}

func TestARoleSessionGetsTheRolesPermissions(t *testing.T) {
	f := newPolicyFixture(t, "app/one", "app/two")
	const roleARN = "arn:aws:iam::000000000000:role/reader"

	_, err := f.ic.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName: aws.String("reader"),
		AssumeRolePolicyDocument: aws.String(policyDoc(statement{
			Effect: "Allow", Action: []string{"sts:AssumeRole"},
			Principal: map[string]any{"AWS": devARN},
		})),
	})
	requireNoErr(t, err, "create the role")
	// The role reads app/one, and only as itself: aws:PrincipalArn is the
	// role's ARN for its sessions.
	_, err = f.ic.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
		RoleName:   aws.String("reader"),
		PolicyName: aws.String("read"),
		PolicyDocument: aws.String(policyDoc(statement{
			Effect: "Allow", Action: []string{"secretsmanager:GetSecretValue"},
			Resource: []string{secretPattern("app/one")},
			Condition: map[string]map[string]any{
				"ArnEquals": {"aws:PrincipalArn": roleARN},
			},
		})),
	})
	requireNoErr(t, err, "put the role's policy")
	// The user may assume the role but read nothing itself.
	putDevPolicy(t, f.ic, allowDoc([]string{"sts:AssumeRole"}, roleARN))

	stsc := sts.New(sts.Options{
		Region:           signingRegion,
		BaseEndpoint:     aws.String(f.id.URL),
		Credentials:      credentials.StaticCredentialsProvider{Value: f.key},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
	assumed, err := stsc.AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn: aws.String(roleARN), RoleSessionName: aws.String("s1"),
	})
	requireNoErr(t, err, "assume the role")
	session := smFor(f.srv, aws.Credentials{
		AccessKeyID:     aws.ToString(assumed.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(assumed.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(assumed.Credentials.SessionToken),
	})
	sessionARN := "arn:aws:sts::000000000000:assumed-role/reader/s1"

	requireEqual(t, getSecretString(t, session, "app/one"), "value of app/one", "session read")
	err = readSecret(session, "app/two")
	requireDenied(t, err, implicitDeny(sessionARN, "secretsmanager:GetSecretValue", "app/two"))
	err = describe(session, "app/one")
	requireDenied(t, err, implicitDeny(sessionARN, "secretsmanager:DescribeSecret", "app/one"))

	err = readSecret(f.dev, "app/one")
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:GetSecretValue", "app/one"))
}

func TestTheRootKeyIsAlwaysAllowed(t *testing.T) {
	// The service's static key is identity's root key: the calls to identity
	// are signed with it. It is never evaluated, though no policy names it.
	f := newPolicyFixture(t, "app/one")
	putDevPolicy(t, f.ic, policyDoc(statement{
		Effect: "Deny", Action: []string{"*"}, Resource: []string{"*"},
	}))

	requireEqual(t, getSecretString(t, f.root, "app/one"), "value of app/one", "root read")
	_, err := f.root.ListSecrets(t.Context(), &awssm.ListSecretsInput{})
	requireNoErr(t, err, "root list")
	_, err = f.root.TagResource(t.Context(), &awssm.TagResourceInput{
		SecretId: aws.String("app/one"),
		Tags:     []smtypes.Tag{{Key: aws.String("k"), Value: aws.String("v")}},
	})
	requireNoErr(t, err, "root tag")
	_, err = f.root.DeleteSecret(t.Context(), &awssm.DeleteSecretInput{
		SecretId: aws.String("app/one"), ForceDeleteWithoutRecovery: aws.Bool(true),
	})
	requireNoErr(t, err, "root delete")
}

func TestStandaloneIsUnchanged(t *testing.T) {
	// Without an identity endpoint the static key is the only key, and it is
	// root: every operation is served without any policy.
	c := newClient(t)
	createSecret(t, c, "app/one", "v1")
	requireEqual(t, getSecretString(t, c, "app/one"), "v1", "read")
	_, err := c.ListSecrets(t.Context(), &awssm.ListSecretsInput{})
	requireNoErr(t, err, "list")
	out, err := c.BatchGetSecretValue(t.Context(), &awssm.BatchGetSecretValueInput{
		SecretIdList: []string{"app/one"},
	})
	requireNoErr(t, err, "batch get")
	requireEqual(t, len(out.SecretValues), 1, "batch values")
	requireNoErr(t, describe(c, "app/one"), "describe")
}

func describeARN(t *testing.T, c *awssm.Client, name string) string {
	t.Helper()
	out, err := c.DescribeSecret(t.Context(), &awssm.DescribeSecretInput{
		SecretId: aws.String(name),
	})
	requireNoErr(t, err, "describe "+name)
	return aws.ToString(out.ARN)
}

func TestDuplicateTagKeysAreRefusedBeforeEvaluation(t *testing.T) {
	f := newPolicyFixture(t, "app/one")
	// dev may create and tag only with env=dev: a repeated key must not let
	// a second value ride along.
	putDevPolicy(t, f.ic, policyDoc(statement{
		Effect:   "Allow",
		Action:   []string{"secretsmanager:CreateSecret", "secretsmanager:TagResource"},
		Resource: []string{"*"},
		Condition: map[string]map[string]any{
			"StringEquals": {"aws:RequestTag/env": "dev"},
		},
	}))
	dup := []smtypes.Tag{
		{Key: aws.String("env"), Value: aws.String("dev")},
		{Key: aws.String("env"), Value: aws.String("prod")},
	}

	for _, c := range []*awssm.Client{f.dev, f.root} {
		_, err := c.CreateSecret(t.Context(), &awssm.CreateSecretInput{
			Name: aws.String("app/dup"), SecretString: aws.String("v"), Tags: dup,
		})
		requireDuplicateTags(t, err)
		_, err = c.TagResource(t.Context(), &awssm.TagResourceInput{
			SecretId: aws.String("app/one"), Tags: dup,
		})
		requireDuplicateTags(t, err)
	}

	out, err := f.root.DescribeSecret(t.Context(), &awssm.DescribeSecretInput{
		SecretId: aws.String("app/one"),
	})
	requireNoErr(t, err, "describe")
	requireEqual(t, len(out.Tags), 0, "tags stored")
	err = describe(f.root, "app/dup")
	requireCode(t, err, "ResourceNotFoundException")
}

func TestAnARNOfAnotherRegionOrAccountIsNotFound(t *testing.T) {
	f := newPolicyFixture(t, "app/one")
	arn := describeARN(t, f.root, "app/one")
	suffix := arn[len(arn)-len("-AbCdEf"):]
	otherRegion := "arn:aws:secretsmanager:eu-west-1:000000000000:secret:app/one" + suffix
	otherAccount := "arn:aws:secretsmanager:us-east-1:111122223333:secret:app/one" + suffix
	// dev may read exactly those two ARNs, which name no secret here.
	putDevPolicy(t, f.ic, policyDoc(statement{
		Effect: "Allow", Action: []string{"secretsmanager:GetSecretValue"},
		Resource: []string{otherRegion, otherAccount},
	}))

	for _, id := range []string{otherRegion, otherAccount} {
		err := readSecret(f.dev, id)
		requireCode(t, err, "ResourceNotFoundException")
		err = readSecret(f.root, id)
		requireCode(t, err, "ResourceNotFoundException")
	}
	err := readSecret(f.dev, arn)
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:GetSecretValue", arn))
}

// requireDuplicateTags fails unless err is Secrets Manager's refusal of
// repeated tag keys.
func requireDuplicateTags(t *testing.T, err error) {
	t.Helper()
	requireCode(t, err, "InvalidParameterException")
	var apiErr smithy.APIError
	errors.As(err, &apiErr) // requireCode has checked it is one
	requireEqual(t, apiErr.ErrorMessage(), "Duplicate tag keys in request", "error message")
}

func TestTheStaticKeyIsRootUnderANonDefaultAccount(t *testing.T) {
	// The static key's principal carries the configured account, so it is
	// that account's root, standalone and with identity.
	c := clientFor(startServer(t, map[string]string{"TULE_Store_AccountID": "444455556666"}))
	arn := createSecret(t, c, "app/one", "v1")
	if !strings.Contains(arn, ":444455556666:") {
		t.Fatalf("ARN %s does not carry the configured account", arn)
	}
	requireEqual(t, getSecretString(t, c, "app/one"), "v1", "standalone read")

	id := startIdentity(t, nil)
	srv := startServer(t, map[string]string{
		"TULE_Store_AccountID":       "444455556666",
		"TULE_Auth_IdentityEndpoint": id.URL,
	})
	root := smFor(srv, rootCreds())
	createSecret(t, root, "app/one", "v1")
	requireEqual(t, getSecretString(t, root, "app/one"), "v1", "read with identity")
}

func TestTagKeysDifferingOnlyByCaseAreRefusedForEvaluatedPrincipals(t *testing.T) {
	f := newPolicyFixture(t)
	putDevPolicy(t, f.ic, allowDoc([]string{"secretsmanager:*"}, "*"))
	tag := func(k, v string) smtypes.Tag { return smtypes.Tag{Key: aws.String(k), Value: aws.String(v)} }

	_, err := f.dev.CreateSecret(t.Context(), &awssm.CreateSecretInput{
		Name: aws.String("app/cased"), SecretString: aws.String("v"),
		Tags: []smtypes.Tag{tag("Env", "dev"), tag("env", "prod")},
	})
	requireDuplicateTags(t, err)

	_, err = f.root.CreateSecret(t.Context(), &awssm.CreateSecretInput{
		Name: aws.String("app/one"), SecretString: aws.String("v"),
		Tags: []smtypes.Tag{tag("Env", "dev")},
	})
	requireNoErr(t, err, "root create")
	_, err = f.dev.TagResource(t.Context(), &awssm.TagResourceInput{
		SecretId: aws.String("app/one"), Tags: []smtypes.Tag{tag("env", "prod")},
	})
	requireDuplicateTags(t, err)
	_, err = f.dev.TagResource(t.Context(), &awssm.TagResourceInput{
		SecretId: aws.String("app/one"), Tags: []smtypes.Tag{tag("Env", "test")},
	})
	requireNoErr(t, err, "replace the stored key")

	// Root writes are unchanged, and a secret holding such keys is never
	// evaluated: its checks fail closed.
	_, err = f.root.TagResource(t.Context(), &awssm.TagResourceInput{
		SecretId: aws.String("app/one"), Tags: []smtypes.Tag{tag("env", "prod")},
	})
	requireNoErr(t, err, "root tag")
	err = readSecret(f.dev, "app/one")
	requireCode(t, err, "InternalServiceError")
	requireEqual(t, getSecretString(t, f.root, "app/one"), "v", "root read")
}

func TestOverlongIdentifiersAreRefusedBeforeEvaluation(t *testing.T) {
	f := newPolicyFixture(t)
	// Twenty wildcard patterns: matching an unbounded identifier against
	// them is the CPU cost the length limits keep bounded.
	patterns := make([]string, 0, 20)
	for i := range 20 {
		patterns = append(patterns, "arn:aws:secretsmanager:*:*:secret:*a*b*"+strconv.Itoa(i))
	}
	putDevPolicy(t, f.ic, policyDoc(statement{
		Effect: "Allow", Action: []string{"secretsmanager:*"}, Resource: patterns,
	}))
	long := strings.Repeat("a", 2049)

	for _, c := range []*awssm.Client{f.dev, f.root} {
		err := readSecret(c, long)
		requireCode(t, err, "ValidationException")
		requireResponse(t, err, http.StatusBadRequest)

		_, err = c.BatchGetSecretValue(t.Context(), &awssm.BatchGetSecretValueInput{
			SecretIdList: []string{"app/one", long},
		})
		requireCode(t, err, "ValidationException")

		_, err = c.CreateSecret(t.Context(), &awssm.CreateSecretInput{
			Name: aws.String(strings.Repeat("n", 513)), SecretString: aws.String("v"),
		})
		requireCode(t, err, "ValidationException")
	}
}

func TestRequestedRegionIsTheServersNotTheSignatures(t *testing.T) {
	f := newPolicyFixture(t, "app/one")
	putDevPolicy(t, f.ic, policyDoc(
		statement{Effect: "Allow", Action: []string{"secretsmanager:*"}, Resource: []string{"*"}},
		statement{
			Effect: "Deny", Action: []string{"secretsmanager:*"}, Resource: []string{"*"},
			Condition: map[string]map[string]any{
				"StringEquals": {"aws:RequestedRegion": "us-east-1"},
			},
		},
	))
	// Signed for eu-west-1, which verifies here, against the us-east-1 store.
	away := clientFor(f.srv, func(o *awssm.Options) {
		o.Region = "eu-west-1"
		o.Credentials = credentials.StaticCredentialsProvider{Value: f.key}
		o.RetryMaxAttempts = 1
	})
	err := readSecret(away, "app/one")
	requireDenied(t, err, explicitDeny(devARN, "secretsmanager:GetSecretValue", "app/one"))
}

func TestEveryOperationIsEvaluated(t *testing.T) {
	// A user with no policy is denied every routed operation on an existing
	// secret, so no operation reaches the store unchecked.
	f := newPolicyFixture(t, "app/one")
	c, ctx, id := f.dev, t.Context(), aws.String("app/one")
	tags := []smtypes.Tag{{Key: aws.String("k"), Value: aws.String("v")}}

	denied[*awssm.BatchGetSecretValueOutput](t, "BatchGetSecretValue")(c.BatchGetSecretValue(
		ctx, &awssm.BatchGetSecretValueInput{SecretIdList: []string{"app/one"}}))
	denied[*awssm.CreateSecretOutput](t, "CreateSecret")(c.CreateSecret(ctx,
		&awssm.CreateSecretInput{Name: aws.String("app/two"), SecretString: aws.String("v")}))
	denied[*awssm.DeleteSecretOutput](t, "DeleteSecret")(c.DeleteSecret(ctx,
		&awssm.DeleteSecretInput{SecretId: id}))
	denied[*awssm.DescribeSecretOutput](t, "DescribeSecret")(c.DescribeSecret(ctx,
		&awssm.DescribeSecretInput{SecretId: id}))
	denied[*awssm.GetSecretValueOutput](t, "GetSecretValue")(c.GetSecretValue(ctx,
		&awssm.GetSecretValueInput{SecretId: id}))
	denied[*awssm.ListSecretVersionIdsOutput](t, "ListSecretVersionIds")(c.ListSecretVersionIds(
		ctx, &awssm.ListSecretVersionIdsInput{SecretId: id}))
	denied[*awssm.ListSecretsOutput](t, "ListSecrets")(c.ListSecrets(ctx,
		&awssm.ListSecretsInput{}))
	denied[*awssm.PutSecretValueOutput](t, "PutSecretValue")(c.PutSecretValue(ctx,
		&awssm.PutSecretValueInput{SecretId: id, SecretString: aws.String("x")}))
	denied[*awssm.RestoreSecretOutput](t, "RestoreSecret")(c.RestoreSecret(ctx,
		&awssm.RestoreSecretInput{SecretId: id}))
	denied[*awssm.TagResourceOutput](t, "TagResource")(c.TagResource(ctx,
		&awssm.TagResourceInput{SecretId: id, Tags: tags}))
	denied[*awssm.UntagResourceOutput](t, "UntagResource")(c.UntagResource(ctx,
		&awssm.UntagResourceInput{SecretId: id, TagKeys: []string{"k"}}))
	denied[*awssm.UpdateSecretOutput](t, "UpdateSecret")(c.UpdateSecret(ctx,
		&awssm.UpdateSecretInput{SecretId: id, Description: aws.String("d")}))
	denied[*awssm.UpdateSecretVersionStageOutput](t, "UpdateSecretVersionStage")(
		c.UpdateSecretVersionStage(ctx, &awssm.UpdateSecretVersionStageInput{
			SecretId: id, VersionStage: aws.String("X"),
			MoveToVersionId: aws.String("00000000-0000-4000-8000-000000000000"),
		}))
}

// denied returns a check, taking an SDK call's results, that op was refused
// with AccessDeniedException.
func denied[T any](t *testing.T, op string) func(T, error) {
	t.Helper()
	return func(_ T, err error) {
		t.Helper()
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDeniedException" {
			t.Errorf("%s: want AccessDeniedException, got %v", op, err)
		}
	}
}

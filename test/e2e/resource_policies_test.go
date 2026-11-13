//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// grantDoc is a resource policy of one statement: effect for principal on
// actions, on "*", as Secrets Manager's examples write them.
func grantDoc(
	effect string,
	principal any,
	actions []string,
	cond map[string]map[string]any,
) string {
	return policyDoc(statement{
		Effect: effect, Principal: map[string]any{"AWS": principal},
		Action: actions, Resource: []string{"*"}, Condition: cond,
	})
}

func putPolicy(t *testing.T, c *awssm.Client, secret, doc string) {
	t.Helper()
	_, err := c.PutResourcePolicy(t.Context(), &awssm.PutResourcePolicyInput{
		SecretId: aws.String(secret), ResourcePolicy: aws.String(doc),
	})
	requireNoErr(t, err, "put the resource policy on "+secret)
}

func resourceExplicitDeny(principal, action, resource string) string {
	return "User: " + principal + " is not authorized to perform: " + action +
		" on resource: " + resource + " with an explicit deny in a resource-based policy"
}

var readAction = []string{"secretsmanager:GetSecretValue"}

func TestTheResourcePolicyAPI(t *testing.T) {
	c := newClient(t)
	arn := createSecret(t, c, "app/one", "v1")
	ctx := t.Context()

	got, err := c.GetResourcePolicy(ctx, &awssm.GetResourcePolicyInput{
		SecretId: aws.String("app/one"),
	})
	requireNoErr(t, err, "get without a policy")
	requireEqual(t, aws.ToString(got.ARN), arn, "ARN")
	requireEqual(t, got.ResourcePolicy == nil, true, "no policy returned")

	doc := grantDoc("Allow", "arn:aws:iam::111122223333:root", readAction, nil)
	put, err := c.PutResourcePolicy(ctx, &awssm.PutResourcePolicyInput{
		SecretId: aws.String("app/one"), ResourcePolicy: aws.String(doc),
		BlockPublicPolicy: aws.Bool(true),
	})
	requireNoErr(t, err, "put")
	requireEqual(t, aws.ToString(put.ARN), arn, "put ARN")
	requireEqual(t, aws.ToString(put.Name), "app/one", "put name")

	got, err = c.GetResourcePolicy(ctx, &awssm.GetResourcePolicyInput{
		SecretId: aws.String(arn),
	})
	requireNoErr(t, err, "get")
	requireEqual(t, aws.ToString(got.ResourcePolicy), doc, "stored policy")

	del, err := c.DeleteResourcePolicy(ctx, &awssm.DeleteResourcePolicyInput{
		SecretId: aws.String("app/one"),
	})
	requireNoErr(t, err, "delete")
	requireEqual(t, aws.ToString(del.Name), "app/one", "delete name")
	got, err = c.GetResourcePolicy(ctx, &awssm.GetResourcePolicyInput{
		SecretId: aws.String("app/one"),
	})
	requireNoErr(t, err, "get after delete")
	requireEqual(t, got.ResourcePolicy == nil, true, "no policy after delete")

	_, err = c.GetResourcePolicy(ctx, &awssm.GetResourcePolicyInput{
		SecretId: aws.String("app/missing"),
	})
	requireAs[*smtypes.ResourceNotFoundException](t, err)
}

func TestPutResourcePolicyRefusals(t *testing.T) {
	c := newClient(t)
	createSecret(t, c, "app/one", "v1")
	put := func(doc string, block bool) error {
		_, err := c.PutResourcePolicy(t.Context(), &awssm.PutResourcePolicyInput{
			SecretId: aws.String("app/one"), ResourcePolicy: aws.String(doc),
			BlockPublicPolicy: aws.Bool(block),
		})
		return err //nolint:wrapcheck // the SDK's error is what the test checks
	}

	// No Principal: an identity-based policy is no resource policy.
	err := put(allowDoc(readAction, "*"), false)
	requireAs[*smtypes.MalformedPolicyDocumentException](t, err)
	requireResponse(t, err, http.StatusBadRequest)
	// A principal IAM refuses.
	err = put(grantDoc("Allow", "arn:aws:iam::111122223333:group/admins", readAction, nil), false)
	requireAs[*smtypes.MalformedPolicyDocumentException](t, err)

	public := grantDoc("Allow", "*", readAction, nil)
	err = put(public, true)
	requireAs[*smtypes.PublicPolicyException](t, err)
	requireResponse(t, err, http.StatusBadRequest)
	// A fixed organization narrows the wildcard.
	requireNoErr(t, put(grantDoc("Allow", "*", readAction, map[string]map[string]any{
		"StringEquals": {"aws:PrincipalOrgID": "o-abc123"},
	}), true), "put an organization-scoped policy")
	// Without BlockPublicPolicy a public policy is stored.
	requireNoErr(t, put(public, false), "put a public policy unblocked")

	// 20,480 characters at most.
	long := grantDoc("Allow", "111122223333", readAction, map[string]map[string]any{
		"StringEquals": {"aws:SourceVpce": strings.Repeat("v", 20480)},
	})
	err = put(long, false)
	requireCode(t, err, "ValidationException")

	_, err = c.DeleteSecret(t.Context(), &awssm.DeleteSecretInput{SecretId: aws.String("app/one")})
	requireNoErr(t, err, "schedule the deletion")
	err = put(public, false)
	requireAs[*smtypes.InvalidRequestException](t, err)
	_, err = c.GetResourcePolicy(t.Context(), &awssm.GetResourcePolicyInput{
		SecretId: aws.String("app/one"),
	})
	requireAs[*smtypes.InvalidRequestException](t, err)
	_, err = c.RestoreSecret(
		t.Context(),
		&awssm.RestoreSecretInput{SecretId: aws.String("app/one")},
	)
	requireNoErr(t, err, "restore")
	got, err := c.GetResourcePolicy(t.Context(), &awssm.GetResourcePolicyInput{
		SecretId: aws.String("app/one"),
	})
	requireNoErr(t, err, "get after restore")
	requireEqual(
		t,
		aws.ToString(got.ResourcePolicy),
		public,
		"the policy kept through the deletion",
	)
}

func TestValidateResourcePolicy(t *testing.T) {
	c := newClient(t)
	createSecret(t, c, "app/one", "v1")
	validate := func(secret *string, doc string) (*awssm.ValidateResourcePolicyOutput, error) {
		//nolint:wrapcheck // the SDK's error is what the test checks
		return c.ValidateResourcePolicy(t.Context(), &awssm.ValidateResourcePolicyInput{
			SecretId: secret, ResourcePolicy: aws.String(doc),
		})
	}

	out, err := validate(aws.String("app/one"), grantDoc("Allow", "111122223333", readAction, nil))
	requireNoErr(t, err, "validate a narrow policy")
	requireEqual(t, out.PolicyValidationPassed, true, "passed")
	requireEqual(t, len(out.ValidationErrors), 0, "errors")

	out, err = validate(nil, grantDoc("Allow", "*", readAction, nil))
	requireNoErr(t, err, "validate a public policy")
	requireEqual(t, out.PolicyValidationPassed, false, "passed")
	requireEqual(t, len(out.ValidationErrors), 1, "errors")
	requireEqual(t, aws.ToString(out.ValidationErrors[0].CheckName), "BROAD_ACCESS", "check name")

	_, err = validate(nil, allowDoc(readAction, "*"))
	requireAs[*smtypes.MalformedPolicyDocumentException](t, err)
	_, err = validate(aws.String("app/missing"), grantDoc("Allow", "111122223333", readAction, nil))
	requireAs[*smtypes.ResourceNotFoundException](t, err)
}

// crossAccountFixture is identity, accounts and secret-store wired together,
// with the user dev in the store's account and the user partner in a member
// account, each with a key.
type crossAccountFixture struct {
	*policyFixture
	partner    *awssm.Client
	partnerIAM *iam.Client
	partnerARN string
}

func newCrossAccountFixture(t *testing.T, secrets ...string) *crossAccountFixture {
	t.Helper()
	accounts := startSibling(t, "accounts", accountsDirEnv, "TULE_Store_Path", nil)
	oc := orgFor(accounts)
	_, err := oc.CreateOrganization(t.Context(), &awsorg.CreateOrganizationInput{})
	requireNoErr(t, err, "create organization")
	created, err := oc.CreateAccount(t.Context(), &awsorg.CreateAccountInput{
		AccountName: aws.String("Partner"), Email: aws.String("partner@example.com"),
	})
	requireNoErr(t, err, "create account")
	st := created.CreateAccountStatus
	if st == nil || st.State != orgtypes.CreateAccountStateSucceeded {
		t.Fatalf("create account: %+v", st)
	}
	member := aws.ToString(st.AccountId)

	id := startIdentity(t, map[string]string{"TULE_Identity_AccountsEndpoint": accounts.URL})
	srv := startWithIdentity(t, id)
	f := &policyFixture{srv: srv, id: id, ic: iamFor(id), root: smFor(srv, rootCreds())}
	for _, name := range secrets {
		createSecret(t, f.root, name, "value of "+name)
	}
	f.key = createUserKey(t, f.ic, "dev")
	f.dev = smFor(srv, f.key)

	// The member account's admin session creates partner there.
	assumed, err := stsFor(id).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn: aws.String(
			"arn:aws:iam::" + member + ":role/OrganizationAccountAccessRole",
		),
		RoleSessionName: aws.String("admin"),
	})
	requireNoErr(t, err, "assume the member account's role")
	pic := iam.New(iam.Options{
		Region:       signingRegion,
		BaseEndpoint: aws.String(id.URL),
		Credentials: credentials.StaticCredentialsProvider{Value: aws.Credentials{
			AccessKeyID:     aws.ToString(assumed.Credentials.AccessKeyId),
			SecretAccessKey: aws.ToString(assumed.Credentials.SecretAccessKey),
			SessionToken:    aws.ToString(assumed.Credentials.SessionToken),
		}},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
	key := createUserKey(t, pic, "partner")
	return &crossAccountFixture{
		policyFixture: f,
		partner:       smFor(srv, key),
		partnerIAM:    pic,
		partnerARN:    "arn:aws:iam::" + member + ":user/partner",
	}
}

func (f *crossAccountFixture) putPartnerPolicy(t *testing.T, doc string) {
	t.Helper()
	_, err := f.partnerIAM.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{
		UserName: aws.String("partner"), PolicyName: aws.String("secrets"),
		PolicyDocument: aws.String(doc),
	})
	requireNoErr(t, err, "put a policy on partner")
}

func TestACrossAccountUserNeedsTheResourcePolicyToo(t *testing.T) {
	f := newCrossAccountFixture(t, "app/shared", "app/private")
	f.putPartnerPolicy(t, allowDoc([]string{"secretsmanager:*"}, "*"))
	putPolicy(t, f.root, "app/shared", grantDoc("Allow", f.partnerARN, readAction, nil))

	shared := describeARN(t, f.root, "app/shared")
	private := describeARN(t, f.root, "app/private")

	requireEqual(t, getSecretString(t, f.partner, shared), "value of app/shared", "granted read")
	// Before resource policies every cross-account request was refused with
	// the resource-based message; now only the one no policy grants is.
	err := readSecret(f.partner, private)
	requireDenied(t, err, resourceDeny(f.partnerARN, "secretsmanager:GetSecretValue", private))

	// Another account must name the secret by ARN: a name is read in the
	// caller's own account, where the store holds nothing, whatever the
	// store's secret of that name grants.
	err = readSecret(f.partner, "app/shared")
	requireAs[*smtypes.ResourceNotFoundException](t, err)

	// The batch is the caller's own action, and each secret is evaluated
	// with its own policy.
	out, err := f.partner.BatchGetSecretValue(t.Context(), &awssm.BatchGetSecretValueInput{
		SecretIdList: []string{shared, private, "app/shared"},
	})
	requireNoErr(t, err, "batch get")
	requireEqual(t, len(out.SecretValues), 1, "values")
	requireEqual(t, aws.ToString(out.SecretValues[0].Name), "app/shared", "value name")
	requireEqual(t, len(out.Errors), 2, "errors")
	requireEqual(t, aws.ToString(out.Errors[0].Message), resourceDeny(f.partnerARN,
		"secretsmanager:GetSecretValue", private), "error message")
	requireEqual(t, aws.ToString(out.Errors[1].ErrorCode), "ResourceNotFoundException",
		"by-name error code")

	// The resource grant alone is not enough across accounts.
	f.putPartnerPolicy(t, allowDoc([]string{"secretsmanager:DescribeSecret"}, "*"))
	err = readSecret(f.partner, shared)
	requireDenied(t, err, implicitDeny(f.partnerARN, "secretsmanager:GetSecretValue", shared))
}

func TestAResourcePolicyDenyBeatsAnIdentityAllow(t *testing.T) {
	f := newPolicyFixture(t, "app/one")
	putDevPolicy(t, f.ic, allowDoc([]string{"secretsmanager:*"}, "*"))
	putPolicy(t, f.root, "app/one", grantDoc("Deny", devARN, readAction, nil))

	err := readSecret(f.dev, "app/one")
	requireDenied(t, err, resourceExplicitDeny(devARN, "secretsmanager:GetSecretValue", "app/one"))
	requireNoErr(t, describe(f.dev, "app/one"), "describe, which the Deny leaves alone")
	// The root key is never evaluated.
	requireEqual(t, getSecretString(t, f.root, "app/one"), "value of app/one", "root read")
}

func TestAResourcePolicyNamingASameAccountUserIsEnoughAlone(t *testing.T) {
	f := newPolicyFixture(t, "app/one", "app/two")
	putPolicy(t, f.root, "app/one", grantDoc("Allow", devARN, readAction, nil))

	requireEqual(t, getSecretString(t, f.dev, "app/one"), "value of app/one", "granted read")
	err := readSecret(f.dev, "app/two")
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:GetSecretValue", "app/two"))
}

func TestAnAccountGrantNeedsTheIdentityAllow(t *testing.T) {
	f := newPolicyFixture(t, "app/one")
	putPolicy(t, f.root, "app/one", grantDoc("Allow", "000000000000", readAction, nil))

	err := readSecret(f.dev, "app/one")
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:GetSecretValue", "app/one"))
	putDevPolicy(t, f.ic, allowDoc(readAction, "*"))
	requireEqual(t, getSecretString(t, f.dev, "app/one"), "value of app/one", "read")
}

func TestARoleSessionIsMatchedByItsRoleARNWithAPath(t *testing.T) {
	f := newPolicyFixture(t, "app/one", "app/two")
	const roleARN = "arn:aws:iam::000000000000:role/team/reader"
	_, err := f.ic.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName: aws.String("reader"), Path: aws.String("/team/"),
		AssumeRolePolicyDocument: aws.String(policyDoc(statement{
			Effect: "Allow", Action: []string{"sts:AssumeRole"},
			Principal: map[string]any{"AWS": devARN},
		})),
	})
	requireNoErr(t, err, "create the role")
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

	// The role has no policy of its own; the grant to its ARN, path
	// included, reaches its session.
	putPolicy(t, f.root, "app/one", grantDoc("Allow", roleARN, readAction, nil))
	requireEqual(t, getSecretString(t, session, "app/one"), "value of app/one", "session read")

	// aws:PrincipalArn carries the path: a Deny scoped to it applies.
	putPolicy(t, f.root, "app/two", policyDoc(
		statement{
			Effect: "Allow", Principal: map[string]any{"AWS": roleARN},
			Action: readAction, Resource: []string{"*"},
		},
		statement{
			Effect: "Deny", Principal: map[string]any{"AWS": "*"},
			Action: readAction, Resource: []string{"*"},
			Condition: map[string]map[string]any{
				"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::000000000000:role/team/*"},
			},
		},
	))
	err = readSecret(session, "app/two")
	requireDenied(t, err, resourceExplicitDeny(sessionARN, "secretsmanager:GetSecretValue",
		"app/two"))
}

func TestAPrincipalTagReachesTheResourcePolicy(t *testing.T) {
	f := newPolicyFixture(t, "app/one")
	_, err := f.ic.TagUser(t.Context(), &iam.TagUserInput{
		UserName: aws.String("dev"),
		Tags:     []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("core")}},
	})
	requireNoErr(t, err, "tag dev")
	tagged := func(team string) string {
		return grantDoc("Allow", devARN, readAction, map[string]map[string]any{
			"StringEquals": {"aws:PrincipalTag/team": team},
		})
	}

	putPolicy(t, f.root, "app/one", tagged("core"))
	requireEqual(t, getSecretString(t, f.dev, "app/one"), "value of app/one", "tagged read")
	putPolicy(t, f.root, "app/one", tagged("ops"))
	err = readSecret(f.dev, "app/one")
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:GetSecretValue", "app/one"))
}

func TestTheResourcePolicyOperationsAreEvaluated(t *testing.T) {
	f := newPolicyFixture(t, "app/one")
	c, ctx, id := f.dev, t.Context(), aws.String("app/one")
	doc := aws.String(grantDoc("Allow", devARN, readAction, nil))

	denied[*awssm.PutResourcePolicyOutput](t, "PutResourcePolicy")(c.PutResourcePolicy(ctx,
		&awssm.PutResourcePolicyInput{SecretId: id, ResourcePolicy: doc}))
	denied[*awssm.GetResourcePolicyOutput](t, "GetResourcePolicy")(c.GetResourcePolicy(ctx,
		&awssm.GetResourcePolicyInput{SecretId: id}))
	denied[*awssm.DeleteResourcePolicyOutput](t, "DeleteResourcePolicy")(c.DeleteResourcePolicy(
		ctx, &awssm.DeleteResourcePolicyInput{SecretId: id}))
	denied[*awssm.ValidateResourcePolicyOutput](t, "ValidateResourcePolicy")(
		c.ValidateResourcePolicy(ctx, &awssm.ValidateResourcePolicyInput{
			SecretId: id, ResourcePolicy: doc,
		}))

	// ValidateResourcePolicy needs PutResourcePolicy as well.
	putDevPolicy(t, f.ic, allowDoc([]string{"secretsmanager:ValidateResourcePolicy"}, "*"))
	_, err := c.ValidateResourcePolicy(ctx, &awssm.ValidateResourcePolicyInput{
		SecretId: id, ResourcePolicy: doc,
	})
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:PutResourcePolicy", "app/one"))
	putDevPolicy(t, f.ic, allowDoc([]string{
		"secretsmanager:ValidateResourcePolicy", "secretsmanager:PutResourcePolicy",
	}, "*"))
	_, err = c.ValidateResourcePolicy(ctx, &awssm.ValidateResourcePolicyInput{
		SecretId: id, ResourcePolicy: doc,
	})
	requireNoErr(t, err, "validate with both actions")
}

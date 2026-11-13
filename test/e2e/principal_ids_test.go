//go:build e2e

package e2e

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// getPolicy returns the resource policy of app/db.
func getPolicy(t *testing.T, c *awssm.Client) string {
	t.Helper()
	out, err := c.GetResourcePolicy(t.Context(), &awssm.GetResourcePolicyInput{
		SecretId: aws.String("app/db"),
	})
	requireNoErr(t, err, "get the resource policy of app/db")
	return aws.ToString(out.ResourcePolicy)
}

// deleteUser deletes the IAM user name and its one access key, as IAM requires
// before the IAM user goes.
func deleteUser(t *testing.T, ic *iam.Client, name, keyID string) {
	t.Helper()
	_, err := ic.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
		UserName: aws.String(name), AccessKeyId: aws.String(keyID),
	})
	requireNoErr(t, err, "delete the access key of "+name)
	_, err = ic.DeleteUser(t.Context(), &iam.DeleteUserInput{UserName: aws.String(name)})
	requireNoErr(t, err, "delete user "+name)
}

func userID(t *testing.T, ic *iam.Client, name string) string {
	t.Helper()
	out, err := ic.GetUser(t.Context(), &iam.GetUserInput{UserName: aws.String(name)})
	requireNoErr(t, err, "get user "+name)
	return aws.ToString(out.User.UserId)
}

// requireInvalidPrincipal fails unless err is MalformedPolicyDocumentException
// for a principal that does not exist.
func requireInvalidPrincipal(t *testing.T, err error) {
	t.Helper()
	requireAs[*smtypes.MalformedPolicyDocumentException](t, err)
	requireResponse(t, err, http.StatusBadRequest)
	var apiErr smithy.APIError
	errors.As(err, &apiErr)
	requireEqual(t, apiErr.ErrorMessage(), "Invalid principal in policy", "error message")
}

// AWS binds a user ARN in a resource policy to that IAM user's unique ID when the
// policy is saved: a user deleted and created again under the same name is
// another principal, which the policy does not name, and the policy then
// shows the old unique ID (IAM User Guide, AWS JSON policy elements:
// Principal).
func TestARecreatedUserDoesNotInheritAResourcePolicyGrant(t *testing.T) {
	id := startIdentity(t, nil)
	srv := startWithIdentity(t, id)
	ic := iamFor(id)
	root := smFor(srv, rootCreds())
	createSecret(t, root, "app/db", "value")

	const readerARN = "arn:aws:iam::000000000000:user/reader"
	key := createUserKey(t, ic, "reader")
	oldID := userID(t, ic, "reader")
	// Same account: a resource policy naming the IAM user is enough on its own.
	doc := grantDoc("Allow", readerARN, readAction, nil)
	putPolicy(t, root, "app/db", doc)

	// While the IAM user exists, the policy reads back with its ARN, as written.
	requireEqual(t, getPolicy(t, root), doc, "the policy while the IAM user exists")
	requireNoErr(t, readSecret(smFor(srv, key), "app/db"), "reader reads")

	deleteUser(t, ic, "reader", key.AccessKeyID)
	again := createUserKey(t, ic, "reader")
	if userID(t, ic, "reader") == oldID {
		t.Fatal("the recreated user has the deleted one's unique ID")
	}

	err := readSecret(smFor(srv, again), "app/db")
	requireDenied(t, err, implicitDeny(readerARN, "secretsmanager:GetSecretValue", "app/db"))
	shown := getPolicy(t, root)
	requireEqual(t, shown, grantDoc("Allow", oldID, readAction, nil),
		"the policy once reader is gone")

	// Saved again, the policy names the new user.
	putPolicy(t, root, "app/db", doc)
	requireNoErr(t, readSecret(smFor(srv, again), "app/db"), "the new user reads once re-granted")
}

func TestAPolicyNamingAUserThatDoesNotExistIsRefused(t *testing.T) {
	id := startIdentity(t, nil)
	srv := startWithIdentity(t, id)
	root := smFor(srv, rootCreds())
	createSecret(t, root, "app/db", "value")

	doc := grantDoc("Allow", "arn:aws:iam::000000000000:user/nobody", readAction, nil)
	_, err := root.PutResourcePolicy(t.Context(), &awssm.PutResourcePolicyInput{
		SecretId: aws.String("app/db"), ResourcePolicy: aws.String(doc),
	})
	requireInvalidPrincipal(t, err)
	requireEqual(t, getPolicy(t, root), "", "no policy stored")

	for _, secret := range []*string{nil, aws.String("app/db")} {
		_, err = root.ValidateResourcePolicy(t.Context(), &awssm.ValidateResourcePolicyInput{
			SecretId: secret, ResourcePolicy: aws.String(doc),
		})
		requireInvalidPrincipal(t, err)
	}

	// Accounts, root ARNs and session ARNs are not bound, and need no user.
	kept := grantDoc("Allow", []string{
		"111122223333", "arn:aws:iam::111122223333:root",
		"arn:aws:sts::111122223333:assumed-role/gone/session",
	}, readAction, nil)
	putPolicy(t, root, "app/db", kept)
	requireEqual(t, getPolicy(t, root), kept, "unbound principals")
}

// Without identity there are no unique IDs: a policy is stored as it was
// sent, a user ARN no one has included.
func TestStandalonePoliciesAreStoredAsSent(t *testing.T) {
	c := newClient(t)
	createSecret(t, c, "app/db", "value")
	doc := grantDoc("Allow", "arn:aws:iam::000000000000:user/nobody", readAction, nil)
	putPolicy(t, c, "app/db", doc)
	requireEqual(t, getPolicy(t, c), doc, "the stored policy")
	out, err := c.ValidateResourcePolicy(t.Context(), &awssm.ValidateResourcePolicyInput{
		ResourcePolicy: aws.String(doc),
	})
	requireNoErr(t, err, "validate")
	requireEqual(t, out.PolicyValidationPassed, true, "validation passed")
}

func createMember(t *testing.T, oc *awsorg.Client, name string) string {
	t.Helper()
	created, err := oc.CreateAccount(t.Context(), &awsorg.CreateAccountInput{
		AccountName: aws.String(name),
		Email:       aws.String(strings.ToLower(name) + "@example.com"),
	})
	requireNoErr(t, err, "create account "+name)
	st := created.CreateAccountStatus
	if st == nil || st.State != orgtypes.CreateAccountStateSucceeded {
		t.Fatalf("create account %s: %+v", name, st)
	}
	return aws.ToString(st.AccountId)
}

func adminSession(t *testing.T, id *sibling, account, name string) aws.Credentials {
	t.Helper()
	out, err := stsFor(id).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn: aws.String(
			"arn:aws:iam::" + account + ":role/OrganizationAccountAccessRole",
		),
		RoleSessionName: aws.String(name),
	})
	requireNoErr(t, err, "assume the role of "+account)
	return aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	}
}

// aws:PrincipalOrgID and aws:PrincipalOrgPaths are supplied for a principal
// whose account is a member of the organization, and left out otherwise
// (IAM User Guide, AWS global condition context keys), so a policy granting
// the organization reaches a member account's session and not that of an
// account removed from it.
func TestAnOrganizationGrantReachesMembersOnly(t *testing.T) {
	accounts := startAccounts(t)
	oc := orgFor(accounts)
	org, err := oc.CreateOrganization(t.Context(), &awsorg.CreateOrganizationInput{})
	requireNoErr(t, err, "create organization")
	roots, err := oc.ListRoots(t.Context(), &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots")
	orgID := aws.ToString(org.Organization.Id)
	path := orgID + "/" + aws.ToString(roots.Roots[0].Id) + "/"
	member := createMember(t, oc, "Member")
	leaving := createMember(t, oc, "Leaving")

	id := startIdentity(t, map[string]string{"TULE_Identity_AccountsEndpoint": accounts.URL})
	srv := startWithIdentity(t, id)
	root := smFor(srv, rootCreds())
	arn := createSecret(t, root, "app/shared", "value")

	// The session is taken while its account is a member, and the account is
	// removed before anything asks for its organization keys, which identity
	// keeps for 30 seconds.
	gone := adminSession(t, id, leaving, "leaving")
	_, err = oc.RemoveAccountFromOrganization(t.Context(),
		&awsorg.RemoveAccountFromOrganizationInput{AccountId: aws.String(leaving)})
	requireNoErr(t, err, "remove the account from the organization")
	in := adminSession(t, id, member, "member")

	for _, cond := range []map[string]map[string]any{
		{"StringEquals": {"aws:PrincipalOrgID": orgID}},
		{"ForAnyValue:StringLike": {"aws:PrincipalOrgPaths": path + "*"}},
	} {
		putPolicy(t, root, "app/shared", grantDoc("Allow", "*", readAction, cond))
		// Both sessions have AdministratorAccess in their own account; the
		// resource policy decides.
		requireNoErr(t, readSecret(smFor(srv, in), arn), "a member account's session reads")
		err = readSecret(smFor(srv, gone), arn)
		requireDenied(t, err, resourceDeny(
			"arn:aws:sts::"+leaving+":assumed-role/OrganizationAccountAccessRole/leaving",
			"secretsmanager:GetSecretValue", arn))
	}
}

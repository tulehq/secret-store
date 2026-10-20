//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

func TestCreateDescribeAndGet(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()

	created, err := c.CreateSecret(ctx, &awssm.CreateSecretInput{
		Name:         aws.String("example/app/db"),
		Description:  aws.String("Local stand-in credentials"),
		SecretString: aws.String(`{"user":"app","password":"placeholder"}`),
		Tags: []types.Tag{
			{Key: aws.String("env"), Value: aws.String("local")},
		},
	})
	requireNoErr(t, err, "create secret")
	requireEqual(t, aws.ToString(created.Name), "example/app/db", "created name")
	if aws.ToString(created.VersionId) == "" {
		t.Fatal("create returned no version ID")
	}
	if !bytes.HasPrefix([]byte(aws.ToString(created.ARN)),
		[]byte("arn:aws:secretsmanager:us-east-1:000000000000:secret:example/app/db-")) {
		t.Fatalf("ARN = %q", aws.ToString(created.ARN))
	}

	got, err := c.GetSecretValue(ctx, &awssm.GetSecretValueInput{
		SecretId: aws.String("example/app/db"),
	})
	requireNoErr(t, err, "get secret value")
	requireEqual(t, aws.ToString(got.SecretString), `{"user":"app","password":"placeholder"}`,
		"secret string")
	if !slices.Equal(got.VersionStages, []string{"AWSCURRENT"}) {
		t.Fatalf("version stages = %v", got.VersionStages)
	}
	if got.CreatedDate == nil {
		t.Fatal("get returned no created date")
	}

	described, err := c.DescribeSecret(ctx, &awssm.DescribeSecretInput{
		SecretId: created.ARN,
	})
	requireNoErr(t, err, "describe secret")
	requireEqual(t, aws.ToString(described.Description), "Local stand-in credentials",
		"description")
	requireEqual(t, len(described.Tags), 1, "tag count")
	requireEqual(t, len(described.VersionIdsToStages), 1, "version map size")
	if described.CreatedDate == nil || described.LastChangedDate == nil {
		t.Fatal("describe returned no dates")
	}
}

func TestCreateDuplicateIsResourceExists(t *testing.T) {
	c := newClient(t)
	createSecret(t, c, "example/taken", "v1")

	_, err := c.CreateSecret(context.Background(), &awssm.CreateSecretInput{
		Name:         aws.String("example/taken"),
		SecretString: aws.String("v2"),
	})
	requireAs[*types.ResourceExistsException](t, err)
}

func TestGetMissingIsResourceNotFound(t *testing.T) {
	c := newClient(t)

	_, err := c.GetSecretValue(context.Background(), &awssm.GetSecretValueInput{
		SecretId: aws.String("example/absent"),
	})
	requireAs[*types.ResourceNotFoundException](t, err)
}

func TestPutAndStagingLabels(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()
	createSecret(t, c, "example/rotating", "v1")

	second, err := c.PutSecretValue(ctx, &awssm.PutSecretValueInput{
		SecretId:     aws.String("example/rotating"),
		SecretString: aws.String("v2"),
	})
	requireNoErr(t, err, "put secret value")
	if !slices.Equal(second.VersionStages, []string{"AWSCURRENT"}) {
		t.Fatalf("new version stages = %v", second.VersionStages)
	}

	requireEqual(t, getSecretString(t, c, "example/rotating"), "v2", "current value")

	previous, err := c.GetSecretValue(ctx, &awssm.GetSecretValueInput{
		SecretId:     aws.String("example/rotating"),
		VersionStage: aws.String("AWSPREVIOUS"),
	})
	requireNoErr(t, err, "get previous value")
	requireEqual(t, aws.ToString(previous.SecretString), "v1", "previous value")

	versions, err := c.ListSecretVersionIds(ctx, &awssm.ListSecretVersionIdsInput{
		SecretId: aws.String("example/rotating"),
	})
	requireNoErr(t, err, "list version IDs")
	requireEqual(t, len(versions.Versions), 2, "version count")
	requireEqual(t, aws.ToString(versions.Versions[0].VersionId),
		aws.ToString(second.VersionId), "newest version first")

	// Promote the older version back, which is how a rollback looks.
	_, err = c.UpdateSecretVersionStage(ctx, &awssm.UpdateSecretVersionStageInput{
		SecretId:            aws.String("example/rotating"),
		VersionStage:        aws.String("AWSCURRENT"),
		MoveToVersionId:     versions.Versions[1].VersionId,
		RemoveFromVersionId: second.VersionId,
	})
	requireNoErr(t, err, "update version stage")
	requireEqual(t, getSecretString(t, c, "example/rotating"), "v1", "value after rollback")
}

func TestBinarySecret(t *testing.T) {
	c := newClient(t)
	want := []byte{0x00, 0x7f, 0x80, 0xff}

	_, err := c.CreateSecret(context.Background(), &awssm.CreateSecretInput{
		Name:         aws.String("example/binary"),
		SecretBinary: want,
	})
	requireNoErr(t, err, "create binary secret")

	got, err := c.GetSecretValue(context.Background(), &awssm.GetSecretValueInput{
		SecretId: aws.String("example/binary"),
	})
	requireNoErr(t, err, "get binary secret")
	if got.SecretString != nil {
		t.Fatal("a binary secret came back as a string")
	}
	if !bytes.Equal(got.SecretBinary, want) {
		t.Fatalf("binary = %v, want %v", got.SecretBinary, want)
	}
}

func TestClientRequestTokenIsIdempotent(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()
	createSecret(t, c, "example/token", "v1")

	in := &awssm.PutSecretValueInput{
		SecretId:           aws.String("example/token"),
		ClientRequestToken: aws.String("22222222-2222-4222-8222-222222222222"),
		SecretString:       aws.String("v2"),
	}
	first, err := c.PutSecretValue(ctx, in)
	requireNoErr(t, err, "put with token")
	again, err := c.PutSecretValue(ctx, in)
	requireNoErr(t, err, "put with the same token")
	requireEqual(t, aws.ToString(again.VersionId), aws.ToString(first.VersionId),
		"retry version ID")

	in.SecretString = aws.String("different")
	_, err = c.PutSecretValue(ctx, in)
	requireAs[*types.ResourceExistsException](t, err)
}

func TestUpdateSecret(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()
	createSecret(t, c, "example/updated", "v1")

	_, err := c.UpdateSecret(ctx, &awssm.UpdateSecretInput{
		SecretId:     aws.String("example/updated"),
		Description:  aws.String("changed"),
		SecretString: aws.String("v2"),
	})
	requireNoErr(t, err, "update secret")

	requireEqual(t, getSecretString(t, c, "example/updated"), "v2", "updated value")

	described, err := c.DescribeSecret(ctx, &awssm.DescribeSecretInput{
		SecretId: aws.String("example/updated"),
	})
	requireNoErr(t, err, "describe secret")
	requireEqual(t, aws.ToString(described.Description), "changed", "updated description")
}

func TestDeleteRestoreAndForceDelete(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()
	createSecret(t, c, "example/doomed", "v1")

	deleted, err := c.DeleteSecret(ctx, &awssm.DeleteSecretInput{
		SecretId: aws.String("example/doomed"),
	})
	requireNoErr(t, err, "delete secret")
	if deleted.DeletionDate == nil {
		t.Fatal("delete returned no deletion date")
	}

	_, err = c.GetSecretValue(ctx, &awssm.GetSecretValueInput{
		SecretId: aws.String("example/doomed"),
	})
	requireAs[*types.InvalidRequestException](t, err)

	// A scheduled secret still describes, which is how its state is visible.
	described, err := c.DescribeSecret(ctx, &awssm.DescribeSecretInput{
		SecretId: aws.String("example/doomed"),
	})
	requireNoErr(t, err, "describe a scheduled secret")
	if described.DeletedDate == nil {
		t.Fatal("describe reported no deleted date")
	}

	_, err = c.RestoreSecret(ctx, &awssm.RestoreSecretInput{
		SecretId: aws.String("example/doomed"),
	})
	requireNoErr(t, err, "restore secret")
	requireEqual(t, getSecretString(t, c, "example/doomed"), "v1", "value after restore")

	_, err = c.DeleteSecret(ctx, &awssm.DeleteSecretInput{
		SecretId:                   aws.String("example/doomed"),
		ForceDeleteWithoutRecovery: aws.Bool(true),
	})
	requireNoErr(t, err, "force delete")

	_, err = c.DescribeSecret(ctx, &awssm.DescribeSecretInput{
		SecretId: aws.String("example/doomed"),
	})
	requireAs[*types.ResourceNotFoundException](t, err)
}

func TestDeleteRejectsAnOutOfRangeRecoveryWindow(t *testing.T) {
	c := newClient(t)
	createSecret(t, c, "example/window", "v1")

	_, err := c.DeleteSecret(context.Background(), &awssm.DeleteSecretInput{
		SecretId:             aws.String("example/window"),
		RecoveryWindowInDays: aws.Int64(1),
	})
	requireAs[*types.InvalidParameterException](t, err)
}

func TestTagging(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()
	createSecret(t, c, "example/tagged", "v1")

	_, err := c.TagResource(ctx, &awssm.TagResourceInput{
		SecretId: aws.String("example/tagged"),
		Tags: []types.Tag{
			{Key: aws.String("env"), Value: aws.String("local")},
			{Key: aws.String("owner"), Value: aws.String("platform")},
		},
	})
	requireNoErr(t, err, "tag resource")

	_, err = c.UntagResource(ctx, &awssm.UntagResourceInput{
		SecretId: aws.String("example/tagged"),
		TagKeys:  []string{"owner"},
	})
	requireNoErr(t, err, "untag resource")

	described, err := c.DescribeSecret(ctx, &awssm.DescribeSecretInput{
		SecretId: aws.String("example/tagged"),
	})
	requireNoErr(t, err, "describe secret")
	requireEqual(t, len(described.Tags), 1, "tag count")
	requireEqual(t, aws.ToString(described.Tags[0].Key), "env", "remaining tag")
}

func TestListSecretsPaginates(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()
	for _, name := range []string{"example/c", "example/a", "example/b"} {
		createSecret(t, c, name, "v")
	}

	first, err := c.ListSecrets(ctx, &awssm.ListSecretsInput{MaxResults: aws.Int32(2)})
	requireNoErr(t, err, "list secrets")
	requireEqual(t, len(first.SecretList), 2, "first page size")
	requireEqual(t, aws.ToString(first.SecretList[0].Name), "example/a", "first name")
	if aws.ToString(first.NextToken) == "" {
		t.Fatal("first page carried no next token")
	}

	second, err := c.ListSecrets(ctx, &awssm.ListSecretsInput{
		MaxResults: aws.Int32(2),
		NextToken:  first.NextToken,
	})
	requireNoErr(t, err, "list secrets page two")
	requireEqual(t, len(second.SecretList), 1, "second page size")
	requireEqual(t, aws.ToString(second.SecretList[0].Name), "example/c", "last name")
	requireEqual(t, aws.ToString(second.NextToken), "", "token on the last page")
}

func TestListSecretsRejectsFilters(t *testing.T) {
	c := newClient(t)

	// Filters are refused rather than ignored, so a filtered listing never
	// looks like it matched everything.
	_, err := c.ListSecrets(context.Background(), &awssm.ListSecretsInput{
		Filters: []types.Filter{{Key: types.FilterNameStringTypeName, Values: []string{"x"}}},
	})
	requireAs[*types.InvalidParameterException](t, err)
}

func TestBatchGetSecretValue(t *testing.T) {
	c := newClient(t)
	createSecret(t, c, "example/one", "1")
	createSecret(t, c, "example/two", "2")

	out, err := c.BatchGetSecretValue(context.Background(), &awssm.BatchGetSecretValueInput{
		SecretIdList: []string{"example/one", "example/two", "example/absent"},
	})
	requireNoErr(t, err, "batch get secret value")
	requireEqual(t, len(out.SecretValues), 2, "values returned")
	requireEqual(t, len(out.Errors), 1, "errors returned")
	requireEqual(t, aws.ToString(out.Errors[0].SecretId), "example/absent", "failed secret")
	requireEqual(t, aws.ToString(out.Errors[0].ErrorCode), "ResourceNotFoundException",
		"error code")
}

func TestUnimplementedOperation(t *testing.T) {
	c := newClient(t)
	createSecret(t, c, "example/unrotated", "v1")

	// Rotation needs a Lambda, so the service says so rather than pretending.
	_, err := c.RotateSecret(context.Background(), &awssm.RotateSecretInput{
		SecretId: aws.String("example/unrotated"),
	})
	requireCode(t, err, "NotImplementedException")
}

func TestListSecretsRejectsASortOrder(t *testing.T) {
	c := newClient(t)

	// Listings are always by name, so a requested order is refused rather
	// than silently ignored.
	_, err := c.ListSecrets(context.Background(), &awssm.ListSecretsInput{
		SortOrder: types.SortOrderTypeDesc,
	})
	requireAs[*types.InvalidParameterException](t, err)
}

func TestKmsKeyIDIsStoredAndEchoed(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()

	// Nothing here encrypts anything, but a client that asks for a key should
	// see its own setting back rather than have it disappear.
	_, err := c.CreateSecret(ctx, &awssm.CreateSecretInput{
		Name:         aws.String("example/keyed"),
		SecretString: aws.String("placeholder"),
		KmsKeyId:     aws.String("alias/example-key"),
	})
	requireNoErr(t, err, "create secret with a KMS key")

	described, err := c.DescribeSecret(ctx, &awssm.DescribeSecretInput{
		SecretId: aws.String("example/keyed"),
	})
	requireNoErr(t, err, "describe secret")
	requireEqual(t, aws.ToString(described.KmsKeyId), "alias/example-key", "described key")

	listed, err := c.ListSecrets(ctx, &awssm.ListSecretsInput{})
	requireNoErr(t, err, "list secrets")
	requireEqual(t, len(listed.SecretList), 1, "secrets listed")
	requireEqual(t, aws.ToString(listed.SecretList[0].KmsKeyId), "alias/example-key",
		"listed key")

	_, err = c.UpdateSecret(ctx, &awssm.UpdateSecretInput{
		SecretId: aws.String("example/keyed"),
		KmsKeyId: aws.String("alias/other-key"),
	})
	requireNoErr(t, err, "update the KMS key")

	described, err = c.DescribeSecret(ctx, &awssm.DescribeSecretInput{
		SecretId: aws.String("example/keyed"),
	})
	requireNoErr(t, err, "describe secret after update")
	requireEqual(t, aws.ToString(described.KmsKeyId), "alias/other-key", "updated key")
}

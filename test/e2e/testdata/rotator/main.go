// Command rotator is a rotation function written as the Secrets Manager
// rotation function template (SecretsManagerRotationTemplate in
// aws-samples/aws-secrets-manager-rotation-lambdas) is, for a secret whose
// value is a password and nothing else, so it has no service to set or test
// the password against: createSecret puts a random password as AWSPENDING,
// setSecret does nothing, testSecret reads the AWSPENDING value, and
// finishSecret moves AWSCURRENT onto it.
//
// It calls Secrets Manager with the AWS SDK's default configuration: the
// credentials its environment gives it, its execution role's session, and
// the endpoint AWS_ENDPOINT_URL_SECRETS_MANAGER names. Two variables make
// it misbehave for the tests: FAIL_STEP fails that step before it calls
// anything, and SLEEP_STEP sleeps two seconds at the start of that step.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type event struct {
	Step               string `json:"Step"`
	SecretID           string `json:"SecretId"`
	ClientRequestToken string `json:"ClientRequestToken"`
}

func handler(ctx context.Context, ev event) error {
	if ev.Step == os.Getenv("SLEEP_STEP") {
		time.Sleep(2 * time.Second)
	}
	if ev.Step == os.Getenv("FAIL_STEP") {
		return fmt.Errorf("%s fails on purpose", ev.Step)
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	c := secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
		o.RetryMaxAttempts = 1
	})
	arn, token := ev.SecretID, ev.ClientRequestToken

	// Make sure the version is staged correctly.
	meta, err := c.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: &arn})
	if err != nil {
		return err
	}
	if !aws.ToBool(meta.RotationEnabled) {
		return fmt.Errorf("secret %s is not enabled for rotation", arn)
	}
	stages, ok := meta.VersionIdsToStages[token]
	switch {
	case !ok:
		return fmt.Errorf("secret version %s has no stage for rotation of secret %s", token, arn)
	case slices.Contains(stages, "AWSCURRENT"):
		return nil
	case !slices.Contains(stages, "AWSPENDING"):
		return fmt.Errorf("secret version %s not set as AWSPENDING for rotation of secret %s",
			token, arn)
	}

	switch ev.Step {
	case "createSecret":
		return createSecret(ctx, c, arn, token)
	case "setSecret":
		return nil
	case "testSecret":
		_, err = c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: &arn, VersionId: &token, VersionStage: aws.String("AWSPENDING"),
		})
		return err
	case "finishSecret":
		return finishSecret(ctx, c, arn, token, meta.VersionIdsToStages)
	default:
		return fmt.Errorf("invalid step parameter %q", ev.Step)
	}
}

func createSecret(ctx context.Context, c *secretsmanager.Client, arn, token string) error {
	if _, err := c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &arn, VersionStage: aws.String("AWSCURRENT"),
	}); err != nil {
		return err
	}
	_, err := c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &arn, VersionId: &token, VersionStage: aws.String("AWSPENDING"),
	})
	var notFound *types.ResourceNotFoundException
	if !errors.As(err, &notFound) {
		return err
	}
	pw, err := c.GetRandomPassword(ctx, &secretsmanager.GetRandomPasswordInput{
		ExcludeCharacters: aws.String(`/@"'\`),
	})
	if err != nil {
		return err
	}
	_, err = c.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId: &arn, ClientRequestToken: &token, SecretString: pw.RandomPassword,
		VersionStages: []string{"AWSPENDING"},
	})
	return err
}

func finishSecret(
	ctx context.Context,
	c *secretsmanager.Client,
	arn, token string,
	versions map[string][]string,
) error {
	var current string
	for id, stages := range versions {
		if slices.Contains(stages, "AWSCURRENT") {
			if id == token {
				return nil
			}
			current = id
		}
	}
	_, err := c.UpdateSecretVersionStage(ctx, &secretsmanager.UpdateSecretVersionStageInput{
		SecretId: &arn, VersionStage: aws.String("AWSCURRENT"),
		MoveToVersionId: &token, RemoveFromVersionId: &current,
	})
	return err
}

func main() {
	lambda.Start(handler)
}

//go:build e2e

package e2e

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// retryDelay is the wait the rotation service makes between a failed
// attempt and the next, on its clock.
const retryDelay = time.Minute

// rotateToken is a client request token, which becomes the AWSPENDING
// version's ID.
const rotateToken = "11111111-2222-4333-8444-555555555555"

func TestARotationMovesTheStagingLabels(t *testing.T) {
	s := newRotationStack(t, rotatorPolicy)
	s.createRotator(t, nil)
	s.allowSecretsManager(t, "")
	before := s.stagesOf(t)["AWSCURRENT"]
	start := s.clock.Now()

	version := s.rotate(t, rotateToken, 30)
	requireEqual(t, version, rotateToken, "the version RotateSecret answers")
	d := s.waitRotated(t, start)

	// finishSecret moved AWSCURRENT onto the new version, and Secrets
	// Manager moved AWSPREVIOUS onto the one it left; AWSPENDING stays on
	// the new version.
	stages := s.stagesOf(t)
	requireEqual(t, stages["AWSCURRENT"], rotateToken, "AWSCURRENT")
	requireEqual(t, stages["AWSPREVIOUS"], before, "AWSPREVIOUS")
	requireEqual(t, stages["AWSPENDING"], rotateToken, "AWSPENDING")
	rotated := getSecretString(t, s.sm, "app/db")
	if rotated == "first-password" || len(rotated) != 32 {
		t.Fatalf("the rotated password is %q, want a new random one", rotated)
	}
	prev, err := s.sm.GetSecretValue(t.Context(), &awssm.GetSecretValueInput{
		SecretId: aws.String("app/db"), VersionStage: aws.String("AWSPREVIOUS"),
	})
	requireNoErr(t, err, "read AWSPREVIOUS")
	requireEqual(t, aws.ToString(prev.SecretString), "first-password", "AWSPREVIOUS value")

	// Each step was invoked once, in order, through the service-invoke
	// endpoint.
	got := s.steps(t)
	if names := stepNames(got); !slices.Equal(names,
		[]string{"createSecret", "setSecret", "testSecret", "finishSecret"}) {
		t.Fatalf("steps = %v", names)
	}
	for _, st := range got {
		requireEqual(t, st.Status, "succeeded", st.Step+" status")
		requireEqual(t, st.Source, "service", st.Step+" source")
	}

	// DescribeSecret and ListSecrets report the configuration and dates.
	requireEqual(t, aws.ToBool(d.RotationEnabled), true, "RotationEnabled")
	requireEqual(t, aws.ToString(d.RotationLambdaARN), rotatorARN, "RotationLambdaARN")
	requireEqual(t, aws.ToInt64(d.RotationRules.AutomaticallyAfterDays), int64(30),
		"AutomaticallyAfterDays")
	last := d.LastRotatedDate.UTC()
	wantNext := time.Date(last.Year(), last.Month(), last.Day()+31, 0, 0, 0, 0, time.UTC)
	requireEqual(t, d.NextRotationDate.UTC(), wantNext, "NextRotationDate")
	list, err := s.sm.ListSecrets(t.Context(), &awssm.ListSecretsInput{})
	requireNoErr(t, err, "list secrets")
	e := list.SecretList[0]
	requireEqual(t, aws.ToBool(e.RotationEnabled), true, "listed RotationEnabled")
	requireEqual(t, aws.ToString(e.RotationLambdaARN), rotatorARN,
		"listed RotationLambdaARN")
	requireEqual(t, aws.ToInt64(e.RotationRules.AutomaticallyAfterDays), int64(30),
		"listed AutomaticallyAfterDays")
	requireEqual(t, e.LastRotatedDate.UTC(), last, "listed LastRotatedDate")
	requireEqual(t, e.NextRotationDate.UTC(), wantNext, "listed NextRotationDate")
}

func TestAScheduledRotationRunsWhenItsWindowOpens(t *testing.T) {
	s := newRotationStack(t, rotatorPolicy)
	s.createRotator(t, nil)
	s.allowSecretsManager(t, s.secretARN)

	s.rotate(t, "", 1)
	first := s.waitRotated(t, s.clock.Now())
	firstValue := getSecretString(t, s.sm, "app/db")

	// The next window is the next UTC day, from midnight. An hour before
	// it, nothing rotates; once it opens, the scheduler rotates the secret.
	now := s.clock.Now()
	window := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	requireEqual(t, first.NextRotationDate.UTC(), window.Add(24*time.Hour), "NextRotationDate")
	s.waitWaits(t, 1)
	s.clock.Advance(window.Add(-time.Hour).Sub(now))
	s.waitWaits(t, 1)
	time.Sleep(200 * time.Millisecond)
	requireEqual(t, getSecretString(t, s.sm, "app/db"), firstValue, "the value before the window")

	s.clock.Advance(90 * time.Minute)
	d := s.waitRotated(t, window)
	if v := getSecretString(t, s.sm, "app/db"); v == firstValue {
		t.Fatal("the scheduled rotation left the value as it was")
	}
	requireEqual(t, d.NextRotationDate.UTC(), window.Add(48*time.Hour), "the next NextRotationDate")
	requireEqual(t, len(s.steps(t)), 8, "invocations of two rotations")
}

func TestAFunctionPolicyWithoutSecretsManagerFailsTheRotation(t *testing.T) {
	s := newRotationStack(t, rotatorPolicy)
	s.createRotator(t, nil)
	// A policy that names another service: Secrets Manager may not invoke
	// the function for this secret.
	_, err := s.lc.AddPermission(t.Context(), &lambda.AddPermissionInput{
		FunctionName: aws.String(rotator), Action: aws.String("lambda:InvokeFunction"),
		StatementId: aws.String("Events"), Principal: aws.String("events.amazonaws.com"),
	})
	requireNoErr(t, err, "add a permission for another service")
	// And one for Secrets Manager acting for another secret: the secret's
	// ARN is the aws:SourceArn the function policy is evaluated with.
	_, err = s.lc.AddPermission(t.Context(), &lambda.AddPermissionInput{
		FunctionName: aws.String(rotator),
		Action:       aws.String("lambda:InvokeFunction"),
		StatementId: aws.String(
			"OtherSecret",
		),
		Principal: aws.String("secretsmanager.amazonaws.com"),
		SourceArn: aws.String(
			"arn:aws:secretsmanager:us-east-1:000000000000:secret:app/other-AbCdEf",
		),
	})
	requireNoErr(t, err, "add a permission for another secret")
	start := s.clock.Now()

	version := s.rotate(t, "", 0)
	s.waitRetrying(t)
	// The invocation was refused, so the function never ran, and the
	// secret is as it was, with the empty AWSPENDING version RotateSecret
	// created.
	requireEqual(t, len(s.steps(t)), 0, "invocations")
	requireEqual(t, getSecretString(t, s.sm, "app/db"), "first-password", "AWSCURRENT value")
	requireEqual(t, s.stagesOf(t)["AWSPENDING"], version, "AWSPENDING")
	_, err = s.sm.GetSecretValue(t.Context(), &awssm.GetSecretValueInput{
		SecretId: aws.String("app/db"), VersionStage: aws.String("AWSPENDING"),
	})
	requireCode(t, err, "ResourceNotFoundException")
	if s.describe(t).LastRotatedDate != nil {
		t.Fatal("a refused rotation recorded a LastRotatedDate")
	}

	// Once the function policy allows Secrets Manager from this secret,
	// the retry rotates it.
	s.allowSecretsManager(t, s.secretARN)
	s.clock.Advance(retryDelay)
	s.waitRotated(t, start)
	requireEqual(t, s.stagesOf(t)["AWSCURRENT"], version, "AWSCURRENT")
}

func TestARotationWithAFailingStepLeavesTheCurrentVersion(t *testing.T) {
	s := newRotationStack(t, rotatorPolicy)
	s.createRotator(t, map[string]string{"FAIL_STEP": "setSecret"})
	s.allowSecretsManager(t, "")
	before := s.stagesOf(t)["AWSCURRENT"]

	version := s.rotate(t, rotateToken, 0)
	// Three attempts, retryDelay apart, then the run is over.
	for range 2 {
		s.waitRetrying(t)
		s.clock.Advance(retryDelay)
	}
	s.waitSteps(t, 6)
	s.waitWaits(t, 1)

	got := s.steps(t)
	want := []string{
		"createSecret", "setSecret", "createSecret", "setSecret",
		"createSecret", "setSecret",
	}
	if names := stepNames(got); !slices.Equal(names, want) {
		t.Fatalf("steps = %v, want %v", names, want)
	}
	for i, st := range got {
		wantStatus := "succeeded"
		if st.Step == "setSecret" {
			wantStatus = "failed"
			requireEqual(t, st.ErrorMessage, "setSecret fails on purpose", "setSecret's error")
		}
		requireEqual(t, st.Status, wantStatus, "status of invocation "+strconv.Itoa(i))
	}

	// AWSCURRENT has not moved; createSecret's value waits as AWSPENDING.
	stages := s.stagesOf(t)
	requireEqual(t, stages["AWSCURRENT"], before, "AWSCURRENT")
	requireEqual(t, stages["AWSPENDING"], version, "AWSPENDING")
	requireEqual(t, getSecretString(t, s.sm, "app/db"), "first-password", "AWSCURRENT value")
	if s.describe(t).LastRotatedDate != nil {
		t.Fatal("a failed rotation recorded a LastRotatedDate")
	}

	// Another rotation is refused while AWSPENDING is apart from AWSCURRENT.
	_, err := s.sm.RotateSecret(t.Context(), &awssm.RotateSecretInput{
		SecretId:           aws.String("app/db"),
		ClientRequestToken: aws.String("99999999-2222-4333-8444-555555555555"),
	})
	requireCode(t, err, "InvalidRequestException")
	requireMessage(t, err, "A previous rotation isn't complete. That rotation will be reattempted.")

	// CancelRotateSecret answers the version the rotation left.
	out, err := s.sm.CancelRotateSecret(t.Context(), &awssm.CancelRotateSecretInput{
		SecretId: aws.String("app/db"),
	})
	requireNoErr(t, err, "cancel the rotation")
	requireEqual(t, aws.ToString(out.VersionId), version, "the canceled version")
}

func TestCancelRotateSecretStopsARotation(t *testing.T) {
	s := newRotationStack(t, rotatorPolicy)
	s.createRotator(t, map[string]string{"SLEEP_STEP": "setSecret"})
	s.allowSecretsManager(t, "")

	version := s.rotate(t, rotateToken, 7)
	// createSecret has run once the pending version has a value; setSecret
	// then sleeps two seconds.
	deadline := time.Now().Add(rotationWait)
	for {
		_, err := s.sm.GetSecretValue(t.Context(), &awssm.GetSecretValueInput{
			SecretId: aws.String("app/db"), VersionStage: aws.String("AWSPENDING"),
		})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("createSecret did not run: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	out, err := s.sm.CancelRotateSecret(t.Context(), &awssm.CancelRotateSecretInput{
		SecretId: aws.String("app/db"),
	})
	requireNoErr(t, err, "cancel the rotation")
	requireEqual(t, aws.ToString(out.VersionId), version, "the canceled version")

	// setSecret finishes on its own; nothing invokes the steps after it.
	time.Sleep(4 * time.Second)
	if names := stepNames(s.steps(t)); slices.Contains(names, "testSecret") ||
		slices.Contains(names, "finishSecret") {
		t.Fatalf("steps = %v, want none after setSecret", names)
	}
	d := s.describe(t)
	requireEqual(t, aws.ToBool(d.RotationEnabled), false, "RotationEnabled")
	requireEqual(t, aws.ToInt64(d.RotationRules.AutomaticallyAfterDays), int64(7),
		"the kept AutomaticallyAfterDays")
	requireEqual(t, aws.ToString(d.RotationLambdaARN), rotatorARN,
		"the kept RotationLambdaARN")
	if d.NextRotationDate != nil || d.LastRotatedDate != nil {
		t.Fatalf("dates with rotation off: next %v, last %v", d.NextRotationDate,
			d.LastRotatedDate)
	}
	requireEqual(t, getSecretString(t, s.sm, "app/db"), "first-password", "AWSCURRENT value")
	requireEqual(t, s.stagesOf(t)["AWSPENDING"], version,
		"AWSPENDING, left for the caller")
}

func TestRotateSecretNeedsInvokeFunctionOnTheFunction(t *testing.T) {
	s := newRotationStack(t, rotatorPolicy)
	s.createRotator(t, nil)
	s.allowSecretsManager(t, "")
	dev := smFor(s.srv, createUserKey(t, s.ic, "dev"))

	putDevPolicy(t, s.ic, allowDoc([]string{"secretsmanager:RotateSecret"},
		secretPattern("app/db")))
	_, err := dev.RotateSecret(t.Context(), &awssm.RotateSecretInput{
		SecretId: aws.String("app/db"), RotationLambdaARN: aws.String(rotatorARN),
	})
	requireDenied(t, err, implicitDeny(devARN, "lambda:InvokeFunction", rotatorARN))

	putDevPolicy(t, s.ic, allowDoc([]string{"lambda:InvokeFunction"}, rotatorARN))
	_, err = dev.RotateSecret(t.Context(), &awssm.RotateSecretInput{
		SecretId: aws.String("app/db"), RotationLambdaARN: aws.String(rotatorARN),
	})
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:RotateSecret", "app/db"))

	putDevPolicy(t, s.ic, policyDoc(
		statement{
			Effect: "Allow", Action: []string{"secretsmanager:RotateSecret"},
			Resource: []string{secretPattern("app/db")},
		},
		statement{
			Effect: "Allow", Action: []string{"lambda:InvokeFunction"},
			Resource: []string{rotatorARN},
		},
	))
	start := s.clock.Now()
	_, err = dev.RotateSecret(t.Context(), &awssm.RotateSecretInput{
		SecretId: aws.String("app/db"), RotationLambdaARN: aws.String(rotatorARN),
	})
	requireNoErr(t, err, "rotate with both permissions")
	s.waitRotated(t, start)

	// CancelRotateSecret is its own action.
	_, err = dev.CancelRotateSecret(t.Context(), &awssm.CancelRotateSecretInput{
		SecretId: aws.String("app/db"),
	})
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:CancelRotateSecret", "app/db"))
}

func TestARotationFunctionsRoleIsHeldToItsPolicy(t *testing.T) {
	// The role may read the secret but not put a value: createSecret's
	// PutSecretValue is denied, by secret-store, to the role's session.
	readOnly := policyDoc(
		statement{Effect: "Allow", Action: []string{
			"secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue",
		}, Resource: []string{"arn:aws:secretsmanager:us-east-1:000000000000:secret:app/*"}},
		statement{
			Effect: "Allow", Action: []string{"secretsmanager:GetRandomPassword"},
			Resource: []string{"*"},
		},
	)
	s := newRotationStack(t, readOnly)
	s.createRotator(t, nil)
	s.allowSecretsManager(t, "")

	s.rotate(t, rotateToken, 0)
	s.waitRetrying(t)

	got := s.steps(t)
	if len(got) != 1 || got[0].Step != "createSecret" || got[0].Status != "failed" {
		t.Fatalf("steps = %+v, want createSecret failed", got)
	}
	session := "arn:aws:sts::000000000000:assumed-role/rotator/rotate"
	if !strings.Contains(got[0].ErrorMessage, implicitDeny(session,
		"secretsmanager:PutSecretValue", s.secretARN)) {
		t.Fatalf("createSecret's error = %q, want PutSecretValue denied to %s",
			got[0].ErrorMessage, session)
	}
	requireEqual(t, getSecretString(t, s.sm, "app/db"), "first-password", "AWSCURRENT value")

	// With PutSecretValue and UpdateSecretVersionStage the retry rotates.
	_, err := s.ic.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
		RoleName: aws.String("rotator"), PolicyName: aws.String("rotation"),
		PolicyDocument: aws.String(rotatorPolicy),
	})
	requireNoErr(t, err, "widen the role's policy")
	start := s.clock.Now()
	s.clock.Advance(retryDelay)
	s.waitRotated(t, start)
}

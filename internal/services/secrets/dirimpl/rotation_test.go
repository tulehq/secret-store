package dirimpl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/schedule"
)

const (
	rotationFn = "arn:aws:lambda:us-east-1:000000000000:function:rotate"
	tokenA     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	tokenB     = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

var rotationNow = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

func unchecked() context.Context { return contracts.Unchecked(context.Background()) }

// startRotation starts a rotation of name to token with the rotation
// function and a 30-day schedule.
func startRotation(t *testing.T, svc *Service, name, token string) *contracts.RotationStarted {
	t.Helper()
	out, err := svc.StartRotation(unchecked(), contracts.StartRotationInput{
		Now: rotationNow, SecretID: name, LambdaARN: rotationFn, Token: token,
		Rules: &schedule.Rules{AutomaticallyAfterDays: 30},
	})
	if err != nil {
		t.Fatalf("start rotation of %s: %v", name, err)
	}
	return out
}

func describeRotation(t *testing.T, svc *Service, name string) *contracts.SecretDetail {
	t.Helper()
	d, err := svc.DescribeSecret(unchecked(), name)
	if err != nil {
		t.Fatalf("describe %s: %v", name, err)
	}
	return d
}

// rotateTo does what a rotation function's createSecret and finishSecret
// do to app/db: it fills the pending version tokenA with v2 and moves
// AWSCURRENT onto it.
func rotateTo(t *testing.T, svc *Service) {
	t.Helper()
	const name, token, value = "app/db", tokenA, "v2"
	if _, err := svc.PutSecretValue(unchecked(), contracts.PutSecretValueInput{
		SecretID: name, VersionID: token, Payload: contracts.Payload{String: str(value)},
		VersionStages: []string{contracts.StagePending},
	}); err != nil {
		t.Fatalf("put the pending value: %v", err)
	}
	moveCurrent(t, svc, name, token)
}

func moveCurrent(t *testing.T, svc *Service, name, token string) {
	t.Helper()
	cur := ""
	for id, stages := range describeRotation(t, svc, name).VersionStages {
		if slices.Contains(stages, contracts.StageCurrent) {
			cur = id
		}
	}
	if _, err := svc.UpdateSecretVersionStage(unchecked(), contracts.UpdateSecretVersionStageInput{
		SecretID: name, VersionStage: contracts.StageCurrent, MoveTo: token, RemoveFrom: cur,
	}); err != nil {
		t.Fatalf("move AWSCURRENT: %v", err)
	}
}

// runIDOf returns the ID of the run on the secret arn, "" when none is.
func runIDOf(t *testing.T, svc *Service, arn string) string {
	t.Helper()
	runs, err := svc.RotationRuns(unchecked())
	want(t, err == nil, "runs: %v", err)
	for _, r := range runs {
		if r.SecretARN == arn {
			return r.ID
		}
	}
	return ""
}

// end ends an attempt of the run on arn.
func end(t *testing.T, svc *Service, arn string, failed bool) *contracts.RotationOutcome {
	t.Helper()
	return endRun(t, svc, arn, runIDOf(t, svc, arn), failed)
}

// endRun ends an attempt of the run runID on arn.
func endRun(t *testing.T, svc *Service, arn, runID string, failed bool) *contracts.RotationOutcome {
	t.Helper()
	out, err := svc.EndRotationAttempt(unchecked(), contracts.EndRotationInput{
		Now: rotationNow.Add(time.Hour), SecretARN: arn, RunID: runID, Failed: failed,
		RetryDelay: time.Minute, MaxAttempts: 2,
	})
	if err != nil {
		t.Fatalf("end the attempt: %v", err)
	}
	return out
}

// want fails the test with the message unless ok.
func want(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

func requireErr(t *testing.T, err, target error, what string) {
	t.Helper()
	want(t, errors.Is(err, target), "%s = %v, want %v", what, err, target)
}

func day(month time.Month, d int) time.Time {
	return time.Date(2026, month, d, 0, 0, 0, 0, time.UTC)
}

func TestStartRotationCreatesAnEmptyPendingVersion(t *testing.T) {
	svc := newTestService(t)
	created := create(t, svc, "app/db", "v1")

	out := startRotation(t, svc, "app/db", tokenA)
	want(t, out.Run != nil, "no run started")
	want(t, out.Run.ID != "", "the run has no ID")
	want(t, *out.Run == contracts.RotationRun{
		ID: out.Run.ID, SecretARN: created.ARN, LambdaARN: rotationFn, Token: tokenA, Attempt: 1,
	}, "run = %+v", out.Run)
	want(t, out.VersionID == tokenA, "version ID = %s, want the token", out.VersionID)

	d := describeRotation(t, svc, "app/db")
	want(t, slices.Equal(d.VersionStages[tokenA], []string{contracts.StagePending}),
		"stages = %v", d.VersionStages)
	want(t, *d.Rotation == contracts.RotationDetail{
		Enabled: true, LambdaARN: rotationFn, Rules: d.Rotation.Rules,
		NextRotationDate: day(time.February, 2),
	}, "rotation = %+v", d.Rotation)
	want(t, *d.Rotation.Rules == schedule.Rules{AutomaticallyAfterDays: 30},
		"rules = %+v", d.Rotation.Rules)

	// The empty version has no value to read, as the rotation templates
	// expect of createSecret's first look.
	_, err := svc.GetSecretValue(unchecked(), contracts.GetSecretValueInput{
		SecretID: "app/db", VersionID: tokenA, VersionStage: contracts.StagePending,
	})
	requireErr(t, err, contracts.ErrVersionNotFound, "read of the empty version")

	// createSecret's PutSecretValue fills it in place, keeping AWSPENDING.
	put, err := svc.PutSecretValue(unchecked(), contracts.PutSecretValueInput{
		SecretID: "app/db", VersionID: tokenA, Payload: contracts.Payload{String: str("v2")},
		VersionStages: []string{contracts.StagePending},
	})
	want(t, err == nil, "fill the pending version: %v", err)
	want(t, slices.Equal(put.VersionStages, []string{contracts.StagePending}),
		"filled version stages = %v", put.VersionStages)
	n := len(describeRotation(t, svc, "app/db").VersionStages)
	want(t, n == 2, "the fill added a version: %d labeled versions", n)
	want(t, currentValue(t, svc, "app/db") == "v1", "the fill moved AWSCURRENT")
}

func TestStartRotationRefusesASecondRotation(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "app/db", "v1")
	startRotation(t, svc, "app/db", tokenA)

	_, err := svc.StartRotation(unchecked(), contracts.StartRotationInput{
		Now: rotationNow, SecretID: "app/db", Token: tokenB,
	})
	requireErr(t, err, contracts.ErrRotationInProgress, "second rotation")
	// Without a token it is a new rotation too.
	_, err = svc.StartRotation(unchecked(), contracts.StartRotationInput{
		Now: rotationNow, SecretID: "app/db",
	})
	requireErr(t, err, contracts.ErrRotationInProgress, "tokenless rotation")

	// The same token is a retry of the request, which starts nothing.
	again := startRotation(t, svc, "app/db", tokenA)
	want(t, *again == contracts.RotationStarted{SecretRef: again.SecretRef, VersionID: tokenA},
		"retried rotation = %+v", again)
}

func TestStartRotationNeedsAFunction(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "app/db", "v1")

	_, err := svc.StartRotation(unchecked(), contracts.StartRotationInput{
		Now: rotationNow, SecretID: "app/db",
	})
	requireErr(t, err, contracts.ErrNoRotationFunction, "rotation without a function")
	want(t, describeRotation(t, svc, "app/db").Rotation == nil,
		"a refused rotation stored a configuration")
}

func TestASucceededRotationRecordsItsDate(t *testing.T) {
	svc := newTestService(t)
	created := create(t, svc, "app/db", "v1")
	startRotation(t, svc, "app/db", tokenA)

	rotateTo(t, svc)
	out := end(t, svc, created.ARN, false)
	want(t, *out == contracts.RotationOutcome{}, "outcome = %+v", out)

	d := describeRotation(t, svc, "app/db")
	want(t, d.Rotation.LastRotatedDate.Equal(rotationNow.Add(time.Hour)),
		"LastRotatedDate = %s", d.Rotation.LastRotatedDate)
	// The next window is the day 30 days after the rotation, 2026-02-01,
	// and NextRotationDate is its end, the latest the rotation happens.
	want(t, d.Rotation.NextRotationDate.Equal(day(time.February, 2)),
		"NextRotationDate = %s", d.Rotation.NextRotationDate)
	want(t, currentValue(t, svc, "app/db") == "v2", "AWSCURRENT is not the rotated value")
	// AWSPENDING stays on the AWSCURRENT version, which is no rotation in
	// progress: a new one may start.
	startRotation(t, svc, "app/db", tokenB)
}

func TestAFinishThatLeavesCurrentUnmovedFails(t *testing.T) {
	svc := newTestService(t)
	created := create(t, svc, "app/db", "v1")
	startRotation(t, svc, "app/db", tokenA)

	out := end(t, svc, created.ARN, false)
	want(t, out.Unmoved, "outcome = %+v, want an unmoved attempt", out)
	want(t, out.Retry != nil, "outcome = %+v, want a retry", out)
	want(t, out.Retry.Attempt == 2, "retry = %+v, want the second attempt", out.Retry)
	want(t, out.Retry.RetryAt.Equal(rotationNow.Add(time.Hour+time.Minute)),
		"RetryAt = %s", out.Retry.RetryAt)

	// The last attempt fails too: the run is over, the pending version
	// stays, and AWSCURRENT is unchanged.
	out = end(t, svc, created.ARN, true)
	want(t, *out == contracts.RotationOutcome{}, "outcome = %+v, want the run over", out)
	want(t, currentValue(t, svc, "app/db") == "v1", "AWSCURRENT moved")
	d := describeRotation(t, svc, "app/db")
	want(t, slices.Contains(d.VersionStages[tokenA], contracts.StagePending),
		"stages = %v, want AWSPENDING kept", d.VersionStages)
	want(t, d.Rotation.LastRotatedDate.IsZero(), "a failed rotation recorded a LastRotatedDate")

	// A rotation to another version is still refused, as AWS refuses one
	// while AWSPENDING is apart from AWSCURRENT; one to the pending
	// version starts it again.
	_, err := svc.StartRotation(unchecked(), contracts.StartRotationInput{
		Now: rotationNow, SecretID: "app/db", Token: tokenB,
	})
	requireErr(t, err, contracts.ErrRotationInProgress, "rotation to another version")
	want(t, startRotation(t, svc, "app/db", tokenA).Run != nil,
		"rotation to the pending version started nothing")
}

func TestATestRotationRemovesItsPendingVersion(t *testing.T) {
	svc := newTestService(t)
	created := create(t, svc, "app/db", "v1")
	out, err := svc.StartRotation(unchecked(), contracts.StartRotationInput{
		Now: rotationNow, SecretID: "app/db", LambdaARN: rotationFn, Token: tokenA,
		TestOnly: true,
	})
	want(t, err == nil, "start the test: %v", err)
	want(t, out.Run.TestOnly, "the run is not a test")

	o := end(t, svc, created.ARN, true)
	want(t, o.Retry == nil, "a test was retried: %+v", o)
	d := describeRotation(t, svc, "app/db")
	_, labeled := d.VersionStages[tokenA]
	want(t, !labeled, "stages = %v, want AWSPENDING removed", d.VersionStages)
	want(t, d.Rotation.Enabled, "the test turned rotation off")
}

func TestCancelRotationTurnsItOffAndEndsTheRun(t *testing.T) {
	svc := newTestService(t)
	created := create(t, svc, "app/db", "v1")
	run := startRotation(t, svc, "app/db", tokenA).Run

	out, err := svc.CancelRotation(unchecked(), "app/db")
	want(t, err == nil, "cancel: %v", err)
	want(t, out.SecretRef == created.SecretRef, "cancel = %+v, want app/db", out)
	want(t, out.VersionID == tokenA, "cancel = %+v, want the pending version", out)
	want(t, out.RunID == run.ID, "cancel ended run %q, want %q", out.RunID, run.ID)

	running, err := svc.RotationRunning(unchecked(), created.ARN, run.ID)
	want(t, err == nil, "running: %v", err)
	want(t, !running, "the run is still on the secret")
	want(t, endRun(t, svc, created.ARN, run.ID, false).Gone, "the canceled run was recorded")

	d := describeRotation(t, svc, "app/db")
	want(t, *d.Rotation == contracts.RotationDetail{LambdaARN: rotationFn, Rules: d.Rotation.Rules},
		"rotation = %+v, want it off, with its function kept and no dates", d.Rotation)
	want(t, d.Rotation.Rules != nil, "the rules were dropped")
	want(t, slices.Contains(d.VersionStages[tokenA], contracts.StagePending),
		"stages = %v, want AWSPENDING left for the caller", d.VersionStages)
}

func TestCancelOnASecretNeverConfiguredChangesNothing(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "app/db", "v1")

	out, err := svc.CancelRotation(unchecked(), "app/db")
	want(t, err == nil, "cancel: %v", err)
	want(t, out.VersionID == "", "cancel answered version %s", out.VersionID)
	want(t, describeRotation(t, svc, "app/db").Rotation == nil, "cancel configured rotation")
}

func TestDeletingASecretEndsItsRun(t *testing.T) {
	svc := newTestService(t)
	created := create(t, svc, "app/db", "v1")
	run := startRotation(t, svc, "app/db", tokenA).Run

	deleted, err := svc.DeleteSecret(unchecked(), contracts.DeleteSecretInput{SecretID: "app/db"})
	want(t, err == nil, "delete: %v", err)
	want(t, deleted.EndedRun == run.ID, "delete ended run %q, want %q", deleted.EndedRun, run.ID)
	running, _ := svc.RotationRunning(unchecked(), created.ARN, run.ID)
	want(t, !running, "a run is on a secret scheduled for deletion")
	runs, err := svc.RotationRuns(unchecked())
	want(t, err == nil, "runs: %v", err)
	want(t, len(runs) == 0, "runs = %v", runs)

	// Restored and rotated again to the same version, the secret has a
	// new run: the old one is not taken for it, though its token is the
	// same.
	_, err = svc.RestoreSecret(unchecked(), "app/db")
	want(t, err == nil, "restore: %v", err)
	again := startRotation(t, svc, "app/db", tokenA).Run
	want(t, again != nil, "the rotation to the pending version started nothing")
	want(t, again.ID != run.ID, "the new run reuses the old one's ID")
	running, _ = svc.RotationRunning(unchecked(), created.ARN, run.ID)
	want(t, !running, "the deleted run is taken for the new one")
	want(t, endRun(t, svc, created.ARN, run.ID, false).Gone, "the deleted run was recorded")
	running, _ = svc.RotationRunning(unchecked(), created.ARN, again.ID)
	want(t, running, "the new run is not running")
}

func TestAForceDeleteReportsTheRunItEnded(t *testing.T) {
	svc := newTestService(t)
	create(t, svc, "app/db", "v1")
	run := startRotation(t, svc, "app/db", tokenA).Run

	deleted, err := svc.DeleteSecret(unchecked(), contracts.DeleteSecretInput{
		SecretID: "app/db", Force: true,
	})
	want(t, err == nil, "delete: %v", err)
	want(t, deleted.EndedRun == run.ID, "delete ended run %q, want %q", deleted.EndedRun, run.ID)
}

func TestATokenNamingAnotherVersionExists(t *testing.T) {
	svc := newTestService(t)
	created := create(t, svc, "app/db", "v1")
	startRotation(t, svc, "app/db", tokenA)
	rotateTo(t, svc)
	end(t, svc, created.ARN, false)

	// The first version, now AWSPREVIOUS, is neither pending nor current.
	_, err := svc.StartRotation(unchecked(), contracts.StartRotationInput{
		Now: rotationNow, SecretID: "app/db", Token: created.VersionID,
	})
	requireErr(t, err, contracts.ErrVersionExists, "rotation to the previous version")
}

func TestATokenOfTheCurrentVersionRepeatsTheRequest(t *testing.T) {
	svc := newTestService(t)
	created := create(t, svc, "app/db", "v1")
	startRotation(t, svc, "app/db", tokenA)
	rotateTo(t, svc)
	end(t, svc, created.ARN, false)
	before := describeRotation(t, svc, "app/db")

	// The SDK retrying the RotateSecret that rotated to tokenA: nothing
	// starts, and nothing changes.
	again := startRotation(t, svc, "app/db", tokenA)
	want(t, again.Run == nil, "the repeat started a run")
	want(t, again.VersionID == tokenA, "the repeat answered %s", again.VersionID)
	after := describeRotation(t, svc, "app/db")
	want(t, after.LastChangedDate.Equal(before.LastChangedDate), "the repeat changed the secret")
	want(t, len(after.VersionStages) == len(before.VersionStages), "the repeat added a version")
}

// due starts the due rotations at now and returns them.
func due(t *testing.T, svc *Service, now time.Time) []contracts.RotationRun {
	t.Helper()
	runs, err := svc.StartDueRotations(unchecked(), now)
	want(t, err == nil, "start the due rotations: %v", err)
	return runs
}

func TestStartDueRotationsStartsOpenWindows(t *testing.T) {
	svc := newTestService(t)
	created := create(t, svc, "app/db", "v1")
	create(t, svc, "app/other", "v1")
	startRotation(t, svc, "app/db", tokenA)
	rotateTo(t, svc)
	end(t, svc, created.ARN, false)

	// The rotation was on 2026-01-02; the next window is the day 30 days
	// after it, 2026-02-01.
	want(t, len(due(t, svc, day(time.February, 1).Add(-time.Hour))) == 0,
		"started before the window")
	opened := day(time.February, 1).Add(30 * time.Minute)
	runs := due(t, svc, opened)
	want(t, len(runs) == 1, "in the window: %v", runs)
	run := runs[0]
	want(t, run == contracts.RotationRun{
		ID: run.ID, SecretARN: created.ARN, LambdaARN: rotationFn, Token: run.Token, Attempt: 1,
		WindowEnd: day(time.February, 2),
	}, "run = %+v", run)
	want(t, run.Token != tokenA, "the run reuses the last rotation's version")
	// A secret with a run is not started twice.
	want(t, len(due(t, svc, opened)) == 0, "started twice")

	// A failed scheduled run is not retried past its window. The schedule
	// still counts from the last rotation, so NextRotationDate is now in
	// the past ("If rotation is unsuccessful, this date may be in the
	// past"), and the failed window is not started again.
	failedAt := run.WindowEnd.Add(-time.Second)
	out, err := svc.EndRotationAttempt(unchecked(), contracts.EndRotationInput{
		Now: failedAt, SecretARN: run.SecretARN, RunID: run.ID,
		Failed: true, RetryDelay: time.Minute, MaxAttempts: 3,
	})
	want(t, err == nil, "end: %v", err)
	want(t, out.Retry == nil, "retried past the window: %+v", out)
	d := describeRotation(t, svc, "app/db")
	want(t, d.Rotation.NextRotationDate.Equal(day(time.February, 2)),
		"NextRotationDate = %s, want the failed window's end", d.Rotation.NextRotationDate)
	want(t, len(due(t, svc, failedAt.Add(time.Minute))) == 0, "the failed window started again")

	// The next window is the one after the failed one: 30 days on from
	// it, 2026-03-03, not a day later.
	want(t, len(due(t, svc, day(time.March, 2).Add(23*time.Hour))) == 0,
		"started before the next window")
	runs = due(t, svc, day(time.March, 3).Add(time.Hour))
	want(t, len(runs) == 1, "next window: %v", runs)
	// It rotates to the version the failed one left.
	want(t, runs[0].Token == run.Token, "next window rotates to %s, want %s again",
		runs[0].Token, run.Token)
	want(t, runs[0].WindowEnd.Equal(day(time.March, 4)), "window end %s", runs[0].WindowEnd)
}

func TestAFailedDailyWindowIsRetriedTheNextDay(t *testing.T) {
	// With AutomaticallyAfterDays 1 and no Duration, the window runs to
	// midnight; a failure in it moves the next attempt to the next day's
	// window, whatever the window's length.
	for _, duration := range []string{"", "23h"} {
		t.Run("Duration "+duration, func(t *testing.T) {
			svc := newTestService(t)
			create(t, svc, "app/db", "v1")
			_, err := svc.StartRotation(unchecked(), contracts.StartRotationInput{
				Now: rotationNow, SecretID: "app/db", LambdaARN: rotationFn, TestOnly: true,
				Rules: &schedule.Rules{AutomaticallyAfterDays: 1, Duration: duration},
			})
			want(t, err == nil, "configure: %v", err)
			arn := describeRotation(t, svc, "app/db").ARN
			end(t, svc, arn, false)

			runs := due(t, svc, day(time.January, 3).Add(time.Hour))
			want(t, len(runs) == 1, "the Jan 3 window: %v", runs)
			_, err = svc.EndRotationAttempt(unchecked(), contracts.EndRotationInput{
				Now: day(time.January, 3).Add(2 * time.Hour), SecretARN: arn, RunID: runs[0].ID,
				Failed: true, RetryDelay: time.Minute, MaxAttempts: 1,
			})
			want(t, err == nil, "end: %v", err)
			want(t, len(due(t, svc, day(time.January, 3).Add(3*time.Hour))) == 0,
				"retried in the failed window")
			runs = due(t, svc, day(time.January, 4).Add(time.Hour))
			want(t, len(runs) == 1, "the Jan 4 window: %v", runs)
		})
	}
}

func TestARunSurvivesARestart(t *testing.T) {
	svc := newTestService(t)
	created := create(t, svc, "app/db", "v1")
	startRotation(t, svc, "app/db", tokenA)

	reopened := NewService(svc.settings)(&gas.NopLogger{})
	want(t, reopened.Init(unchecked()) == nil, "init the reopened store")
	defer func() { _ = reopened.Close(unchecked()) }()

	runs, err := reopened.RotationRuns(unchecked())
	want(t, err == nil, "runs: %v", err)
	want(t, len(runs) == 1, "runs = %v", runs)
	want(t, runs[0] == contracts.RotationRun{
		ID: runs[0].ID, SecretARN: created.ARN, LambdaARN: rotationFn, Token: tokenA, Attempt: 1,
	}, "run = %+v", runs[0])
}

func TestARecordWithoutRotationLoads(t *testing.T) {
	// A record as every version before rotation wrote it: no "rotation".
	svc := newTestService(t)
	old := `{"createdDate":"2026-01-01T00:00:00Z","lastChangedDate":"2026-01-01T00:00:00Z",` +
		`"name":"app/old","arn":"arn:aws:secretsmanager:us-east-1:000000000000:secret:app/old-AbCdEf",` +
		`"versions":[{"createdDate":"2026-01-01T00:00:00Z","secretString":"v1",` +
		`"versionId":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","stages":["AWSCURRENT"]}]}`
	err := os.WriteFile(filepath.Join(svc.settings.RootDir, fileName("app/old")),
		[]byte(old), filePerm)
	want(t, err == nil, "write the old record: %v", err)

	d := describeRotation(t, svc, "app/old")
	want(t, d.Rotation == nil, "rotation = %+v, want none", d.Rotation)
	want(t, currentValue(t, svc, "app/old") == "v1", "the old record's value")
	startRotation(t, svc, "app/old", tokenA)
}

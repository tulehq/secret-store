package rotation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/schedule"
	"tule.dev/secret-store/internal/services/secrets/dirimpl"
)

const rotationFn = "arn:aws:lambda:us-east-1:000000000000:function:rotate"

func unchecked() context.Context { return contracts.Unchecked(context.Background()) }

// fakeClock is a Clock that moves only when the test advances it.
type fakeClock struct {
	now     time.Time
	waiters []waiter
	mu      sync.Mutex
}

type waiter struct {
	at time.Time
	ch chan time.Time
}

// newFakeClock returns a fake clock at the system's time: the store dates
// versions on the system's clock, and the next rotation window counts from
// the current version's date, so the two start together.
func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Now().UTC()}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
		return ch
	}
	c.waiters = append(c.waiters, waiter{at: c.now.Add(d), ch: ch})
	return ch
}

// Advance moves the clock on by d and fires every wait that has ended.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	kept := c.waiters[:0]
	for _, w := range c.waiters {
		if w.at.After(c.now) {
			kept = append(kept, w)
			continue
		}
		w.ch <- c.now
	}
	c.waiters = kept
}

// waiting returns how many waits are pending.
func (c *fakeClock) waiting() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}

// fakeFunction is a rotation function written the way the User Guide's
// template is, run against the store directly: createSecret puts a new
// value as AWSPENDING, finishSecret moves AWSCURRENT onto it. It records the
// steps it is invoked for; failStep makes that step fail, and block, when
// set, holds that step until it is closed or the invocation is canceled.
type fakeFunction struct {
	store    contracts.SecretsProvider
	block    chan struct{}
	reached  chan string
	failStep string
	blockAt  string
	steps    []string
	mu       sync.Mutex
	skipMove bool
}

func (f *fakeFunction) Invoke(
	ctx context.Context,
	function string,
	payload []byte,
	secretARN string,
) (*StepResult, error) {
	var ev stepEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		return nil, fmt.Errorf("decode the event: %w", err)
	}
	if function != rotationFn || ev.SecretID != secretARN {
		return nil, errors.New("invoked for the wrong function or secret")
	}
	f.mu.Lock()
	f.steps = append(f.steps, ev.Step)
	failStep, blockAt, block := f.failStep, f.blockAt, f.block
	f.mu.Unlock()
	if f.reached != nil {
		f.reached <- ev.Step
	}
	if ev.Step == blockAt {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, fmt.Errorf("the invocation was canceled: %w", ctx.Err())
		}
	}
	if ev.Step == failStep {
		return &StepResult{
			FunctionError: "Unhandled",
			Payload:       []byte(`{"errorMessage":"no"}`),
		}, nil
	}
	return &StepResult{}, f.apply(contracts.Unchecked(ctx), ev)
}

func (f *fakeFunction) apply(ctx context.Context, ev stepEvent) error {
	switch ev.Step {
	case "createSecret":
		v := "rotated-" + ev.ClientRequestToken
		_, err := f.store.PutSecretValue(ctx, contracts.PutSecretValueInput{
			SecretID: ev.SecretID, VersionID: ev.ClientRequestToken,
			Payload: contracts.Payload{String: &v}, VersionStages: []string{contracts.StagePending},
		})
		return err
	case "finishSecret":
		if f.skipMove {
			return nil
		}
		d, err := f.store.DescribeSecret(ctx, ev.SecretID)
		if err != nil {
			return err
		}
		var cur string
		for id, stages := range d.VersionStages {
			if slices.Contains(stages, contracts.StageCurrent) {
				cur = id
			}
		}
		_, err = f.store.UpdateSecretVersionStage(ctx, contracts.UpdateSecretVersionStageInput{
			SecretID: ev.SecretID, VersionStage: contracts.StageCurrent,
			MoveTo: ev.ClientRequestToken, RemoveFrom: cur,
		})
		return err
	}
	return nil
}

func (f *fakeFunction) invoked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.steps)
}

type fixture struct {
	store *dirimpl.Service
	svc   *Service
	fn    *fakeFunction
	clock *fakeClock
	arn   string
}

// newFixture returns a rotation service over a fresh store holding app/db,
// with a fake function and clock.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	store := dirimpl.NewService(&dirimpl.Settings{
		RootDir: t.TempDir(), Region: "us-east-1", AccountID: "000000000000",
	})(&gas.NopLogger{})
	if err := store.Init(unchecked()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(unchecked()) })
	v := "v1"
	created, err := store.CreateSecret(unchecked(), contracts.CreateSecretInput{
		Name: "app/db", Payload: contracts.Payload{String: &v},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		store: store, fn: &fakeFunction{store: store}, clock: newFakeClock(), arn: created.ARN,
	}
	f.svc = f.start(t)
	return f
}

// start starts a rotation service over the fixture's store, stopped when
// the test ends.
func (f *fixture) start(t *testing.T) *Service {
	t.Helper()
	svc := NewService(Settings{Invoker: f.fn, Clock: f.clock})(&gas.NopLogger{}, f.store)
	if err := svc.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })
	return svc
}

func (f *fixture) rotate(t *testing.T, in contracts.StartRotationInput) *contracts.RotationStarted {
	t.Helper()
	if in.SecretID == "" {
		in.SecretID = "app/db"
	}
	if in.LambdaARN == "" {
		in.LambdaARN = rotationFn
	}
	out, err := f.svc.Rotate(unchecked(), in)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	return out
}

func (f *fixture) current(t *testing.T) string {
	t.Helper()
	out, err := f.store.GetSecretValue(
		unchecked(),
		contracts.GetSecretValueInput{SecretID: "app/db"},
	)
	if err != nil {
		t.Fatal(err)
	}
	return *out.Payload.String
}

func (f *fixture) describe(t *testing.T) *contracts.SecretDetail {
	t.Helper()
	d, err := f.store.DescribeSecret(unchecked(), "app/db")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// waitFor polls cond until it holds, failing the test after a few seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// settled waits until the secret has no run, which every ended run leaves.
func (f *fixture) settled(t *testing.T) {
	t.Helper()
	waitFor(t, "the run to end", func() bool { return f.runID(t) == "" })
}

// runID returns the ID of the run on the secret, "" when none is.
func (f *fixture) runID(t *testing.T) string {
	t.Helper()
	runs, err := f.store.RotationRuns(unchecked())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range runs {
		if r.SecretARN == f.arn {
			return r.ID
		}
	}
	return ""
}

func TestARotationInvokesTheFourStepsInOrder(t *testing.T) {
	f := newFixture(t)
	out := f.rotate(t, contracts.StartRotationInput{
		Token: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
	})
	f.settled(t)

	if got := f.fn.invoked(); !slices.Equal(got, steps) {
		t.Fatalf("steps = %v, want %v", got, steps)
	}
	if got, want := f.current(t), "rotated-"+out.VersionID; got != want {
		t.Fatalf("current = %s, want %s", got, want)
	}
	d := f.describe(t)
	if !d.Rotation.LastRotatedDate.Equal(f.clock.Now()) {
		t.Fatalf("LastRotatedDate = %s, want %s", d.Rotation.LastRotatedDate, f.clock.Now())
	}
	var previous string
	for id, stages := range d.VersionStages {
		if slices.Contains(stages, contracts.StagePrevious) {
			previous = id
		}
	}
	if previous == "" || previous == out.VersionID {
		t.Fatalf("stages = %v, want AWSPREVIOUS on the old version", d.VersionStages)
	}
}

func TestAFailingStepIsRetriedThenGivesUp(t *testing.T) {
	f := newFixture(t)
	f.fn.failStep = "setSecret"
	out := f.rotate(t, contracts.StartRotationInput{})

	// Each attempt runs createSecret and the failing setSecret, then waits
	// retryDelay on the clock for the next.
	for attempt := 1; attempt < maxAttempts; attempt++ {
		waitFor(t, "the retry wait", func() bool {
			return len(f.fn.invoked()) == 2*attempt && f.clock.waiting() >= 2
		})
		f.clock.Advance(retryDelay)
	}
	f.settled(t)

	want := make([]string, 0, 2*maxAttempts)
	for range maxAttempts {
		want = append(want, "createSecret", "setSecret")
	}
	if got := f.fn.invoked(); !slices.Equal(got, want) {
		t.Fatalf("steps = %v, want %v", got, want)
	}
	if got := f.current(t); got != "v1" {
		t.Fatalf("current = %s, want v1 unchanged", got)
	}
	if !slices.Contains(f.describe(t).VersionStages[out.VersionID], contracts.StagePending) {
		t.Fatal("the failed rotation's AWSPENDING version is gone")
	}
}

func TestAFinishThatDoesNotMoveCurrentFails(t *testing.T) {
	f := newFixture(t)
	f.fn.skipMove = true
	out := f.rotate(t, contracts.StartRotationInput{})

	waitFor(t, "the retry wait", func() bool { return f.clock.waiting() >= 2 })
	if !f.describe(t).Rotation.LastRotatedDate.IsZero() {
		t.Fatal("an unmoved finish recorded a rotation")
	}
	running, err := f.store.RotationRunning(unchecked(), f.arn, out.Run.ID)
	if err != nil || !running {
		t.Fatalf("running = %v, %v, want the run waiting to retry", running, err)
	}
}

func TestASecondRotationIsRefusedWhileOneRuns(t *testing.T) {
	f := newFixture(t)
	f.fn.blockAt, f.fn.block = "setSecret", make(chan struct{})
	first := f.rotate(t, contracts.StartRotationInput{})

	_, err := f.svc.Rotate(unchecked(), contracts.StartRotationInput{
		SecretID: "app/db", LambdaARN: rotationFn,
	})
	if !errors.Is(err, contracts.ErrRotationInProgress) {
		t.Fatalf("second rotation = %v, want ErrRotationInProgress", err)
	}
	// Repeating the first request is no second rotation.
	again := f.rotate(t, contracts.StartRotationInput{Token: first.VersionID})
	if again.Run != nil {
		t.Fatal("the repeated request started a run")
	}

	close(f.fn.block)
	f.settled(t)
	if got := f.fn.invoked(); !slices.Equal(got, steps) {
		t.Fatalf("steps = %v, want one rotation's", got)
	}
}

func TestCancelStopsARotationMidway(t *testing.T) {
	f := newFixture(t)
	f.fn.blockAt, f.fn.block = "setSecret", make(chan struct{})
	f.fn.reached = make(chan string, 8)
	out := f.rotate(t, contracts.StartRotationInput{})
	for step := range f.fn.reached {
		if step == "setSecret" {
			break
		}
	}

	canceled, err := f.svc.Cancel(unchecked(), "app/db")
	if err != nil {
		t.Fatal(err)
	}
	if canceled.VersionID != out.VersionID {
		t.Fatalf("cancel answered version %s, want %s", canceled.VersionID, out.VersionID)
	}
	f.settled(t)
	// The run's goroutine has ended: nothing invokes the next steps.
	time.Sleep(50 * time.Millisecond)
	if got := f.fn.invoked(); !slices.Equal(got, []string{"createSecret", "setSecret"}) {
		t.Fatalf("steps = %v, want none after setSecret", got)
	}
	if f.describe(t).Rotation.Enabled {
		t.Fatal("rotation is still on")
	}
	if got := f.current(t); got != "v1" {
		t.Fatalf("current = %s, want v1", got)
	}
}

func TestARunInterruptedByAShutdownIsResumed(t *testing.T) {
	f := newFixture(t)
	f.fn.blockAt, f.fn.block = "testSecret", make(chan struct{})
	f.fn.reached = make(chan string, 8)
	out := f.rotate(t, contracts.StartRotationInput{})
	for step := range f.fn.reached {
		if step == "testSecret" {
			break
		}
	}

	// Close cancels the invocation in flight and waits; the run stays in
	// the store.
	if err := f.svc.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	running, err := f.store.RotationRunning(unchecked(), f.arn, out.Run.ID)
	if err != nil || !running {
		t.Fatalf("running after shutdown = %v, %v", running, err)
	}

	// The next start resumes it from createSecret, to the same version.
	f.fn.blockAt = ""
	f.svc = f.start(t)
	f.settled(t)
	want := make([]string, 0, 3+len(steps))
	want = append(want, "createSecret", "setSecret", "testSecret")
	want = append(want, steps...)
	if got := f.fn.invoked(); !slices.Equal(got, want) {
		t.Fatalf("steps = %v, want %v", got, want)
	}
	if got, w := f.current(t), "rotated-"+out.VersionID; got != w {
		t.Fatalf("current = %s, want %s", got, w)
	}
}

func TestATestRotationOnlyRunsTestSecret(t *testing.T) {
	f := newFixture(t)
	out := f.rotate(t, contracts.StartRotationInput{TestOnly: true})
	f.settled(t)

	if got := f.fn.invoked(); !slices.Equal(got, []string{"testSecret"}) {
		t.Fatalf("steps = %v, want testSecret alone", got)
	}
	if _, ok := f.describe(t).VersionStages[out.VersionID]; ok {
		t.Fatal("the test's AWSPENDING version is still labeled")
	}
}

func TestTheSchedulerRotatesWhenTheWindowOpens(t *testing.T) {
	f := newFixture(t)
	f.rotate(t, contracts.StartRotationInput{
		Rules: &schedule.Rules{ScheduleExpression: "rate(1 day)"},
	})
	f.settled(t)
	first := f.current(t)

	// The next window is tomorrow's, from midnight UTC.
	now := f.clock.Now()
	tomorrow := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	waitFor(t, "the scheduler's wait", func() bool { return f.clock.waiting() >= 1 })
	f.clock.Advance(tomorrow.Add(-time.Hour).Sub(now))
	time.Sleep(50 * time.Millisecond)
	if got := f.current(t); got != first {
		t.Fatal("rotated before the window opened")
	}
	waitFor(t, "the scheduler's wait", func() bool { return f.clock.waiting() >= 1 })
	f.clock.Advance(2 * time.Hour)
	waitFor(t, "the scheduled rotation", func() bool { return f.current(t) != first })

	waitFor(t, "the rotation's date", func() bool {
		return !f.describe(t).Rotation.LastRotatedDate.Before(tomorrow)
	})
	// The one after is the day after tomorrow's, which ends the day after.
	d := f.describe(t)
	if want := tomorrow.AddDate(0, 0, 2); !d.Rotation.NextRotationDate.Equal(want) {
		t.Fatalf("NextRotationDate = %s, want %s", d.Rotation.NextRotationDate, want)
	}
}

func TestWithoutAnInvokerNothingIsServed(t *testing.T) {
	f := newFixture(t)
	svc := NewService(Settings{})(&gas.NopLogger{}, f.store)
	if err := svc.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Close(context.Background()) }()
	if svc.Available() {
		t.Fatal("available without an invoker")
	}
	if _, err := svc.Rotate(
		unchecked(),
		contracts.StartRotationInput{SecretID: "app/db"},
	); err == nil {
		t.Fatal("rotated without an invoker")
	}
}

// configure changes the fake function under its lock, for a test that
// changes it while invocations run.
func (f *fakeFunction) configure(change func(*fakeFunction)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

// count returns how many times step was invoked.
func (f *fakeFunction) count(step string) int {
	n := 0
	for _, s := range f.invoked() {
		if s == step {
			n++
		}
	}
	return n
}

// awaitStep waits until the fake function reaches step.
func (f *fakeFunction) awaitStep(t *testing.T, step string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-f.reached:
			if got == step {
				return
			}
		case <-deadline:
			t.Fatalf("the function did not reach %s", step)
		}
	}
}

// cancelHook is the store with a hook that runs after CancelRotation has
// ended the run and before it returns, so a test can put a request between
// the store's cancel and the service's.
type cancelHook struct {
	*dirimpl.Service
	afterCancel func()
}

func (h *cancelHook) CancelRotation(
	ctx context.Context,
	secretID string,
) (*contracts.RotationCanceled, error) {
	out, err := h.Service.CancelRotation(ctx, secretID)
	if err == nil && h.afterCancel != nil {
		h.afterCancel()
	}
	return out, err
}

func TestACancelStopsOnlyTheRunItEnded(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	hook := &cancelHook{Service: f.store}
	f.svc = NewService(Settings{Invoker: f.fn, Clock: f.clock})(&gas.NopLogger{}, hook)
	if err := f.svc.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.svc.Close(context.Background()) })

	f.fn.blockAt, f.fn.block = "setSecret", make(chan struct{})
	f.fn.reached = make(chan string, 16)
	first := f.rotate(t, contracts.StartRotationInput{})
	f.fn.awaitStep(t, "setSecret")

	// Between the store's cancel and the service's, a RotateSecret starts
	// a rotation of its own, to the version the canceled one left. The
	// cancel stops the run it ended, never the new one.
	var second *contracts.RotationStarted
	hook.afterCancel = func() {
		f.fn.configure(func(fn *fakeFunction) { fn.blockAt = "" })
		second = f.rotate(t, contracts.StartRotationInput{Token: first.VersionID})
	}
	if _, err := f.svc.Cancel(unchecked(), "app/db"); err != nil {
		t.Fatal(err)
	}

	f.settled(t)
	if got, want := f.current(t), "rotated-"+second.VersionID; got != want {
		t.Fatalf("current = %s, want %s: the second rotation did not complete", got, want)
	}
}

func TestADeletedSecretsRunNeverRunsBesideTheNextOne(t *testing.T) {
	f := newFixture(t)
	f.fn.blockAt, f.fn.block = "setSecret", make(chan struct{})
	f.fn.reached = make(chan string, 16)
	first := f.rotate(t, contracts.StartRotationInput{})
	f.fn.awaitStep(t, "setSecret")

	// Deleted mid-step without its goroutine being stopped, restored, and
	// rotated again to the same pending version: the first run, once its
	// step returns, sees it is no longer the secret's, though its token is
	// the new run's.
	if _, err := f.store.DeleteSecret(unchecked(), contracts.DeleteSecretInput{
		SecretID: "app/db",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RestoreSecret(unchecked(), "app/db"); err != nil {
		t.Fatal(err)
	}
	f.fn.configure(func(fn *fakeFunction) { fn.blockAt = "" })
	second := f.rotate(t, contracts.StartRotationInput{Token: first.VersionID})
	if second.Run == nil || second.Run.ID == first.Run.ID {
		t.Fatalf("the second rotation = %+v, want a run of its own", second.Run)
	}
	close(f.fn.block)

	f.settled(t)
	time.Sleep(50 * time.Millisecond)
	for _, step := range []string{"testSecret", "finishSecret"} {
		if n := f.fn.count(step); n != 1 {
			t.Fatalf("%s invoked %d times, want once: the deleted run went on (%v)",
				step, n, f.fn.invoked())
		}
	}
}

func TestDeletingASecretStopsItsRunsGoroutine(t *testing.T) {
	f := newFixture(t)
	f.fn.blockAt, f.fn.block = "setSecret", make(chan struct{})
	f.fn.reached = make(chan string, 16)
	f.rotate(t, contracts.StartRotationInput{})
	f.fn.awaitStep(t, "setSecret")

	deleted, err := f.store.DeleteSecret(unchecked(), contracts.DeleteSecretInput{
		SecretID: "app/db",
	})
	if err != nil {
		t.Fatal(err)
	}
	// What the module does with DeleteSecret's answer: the step in flight
	// is abandoned, as its context ends, and nothing follows it.
	f.svc.StopRun(deleted.EndedRun)
	waitFor(t, "the run's goroutine to stop", func() bool { return f.svc.runs.size() == 0 })
	if got := f.fn.invoked(); !slices.Equal(got, []string{"createSecret", "setSecret"}) {
		t.Fatalf("steps = %v, want none after setSecret", got)
	}
}

func TestAFailedRotationCanBeStartedAgainWithItsToken(t *testing.T) {
	f := newFixture(t)
	f.svc.maxAttempts = 1
	f.fn.failStep = "setSecret"
	out := f.rotate(t, contracts.StartRotationInput{})
	f.settled(t)
	if !slices.Contains(f.describe(t).VersionStages[out.VersionID], contracts.StagePending) {
		t.Fatal("the failed rotation left no AWSPENDING version")
	}

	f.fn.configure(func(fn *fakeFunction) { fn.failStep = "" })
	again := f.rotate(t, contracts.StartRotationInput{Token: out.VersionID})
	if again.Run == nil {
		t.Fatal("the rotation to the pending version started nothing")
	}
	f.settled(t)
	if got, want := f.current(t), "rotated-"+out.VersionID; got != want {
		t.Fatalf("current = %s, want %s", got, want)
	}
}

func TestAServiceClosedAndInitializedAgainRotates(t *testing.T) {
	f := newFixture(t)
	f.fn.blockAt, f.fn.block = "testSecret", make(chan struct{})
	f.fn.reached = make(chan string, 16)
	out := f.rotate(t, contracts.StartRotationInput{})
	f.fn.awaitStep(t, "testSecret")

	// gas's RestartService: Close, then Init on the same instance.
	if err := f.svc.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.fn.configure(func(fn *fakeFunction) { fn.blockAt = "" })
	if err := f.svc.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.settled(t)
	if got, want := f.current(t), "rotated-"+out.VersionID; got != want {
		t.Fatalf("current = %s, want %s: the run was not resumed", got, want)
	}

	// And it serves new rotations.
	next := f.rotate(t, contracts.StartRotationInput{})
	f.settled(t)
	if got, want := f.current(t), "rotated-"+next.VersionID; got != want {
		t.Fatalf("current = %s, want %s", got, want)
	}
}

func TestNoStepIsInvokedBeforeTheServerServes(t *testing.T) {
	f := newFixture(t)
	if err := f.svc.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A run left in the store, as a shutdown leaves one.
	if _, err := f.store.StartRotation(unchecked(), contracts.StartRotationInput{
		Now: f.clock.Now(), SecretID: "app/db", LambdaARN: rotationFn,
	}); err != nil {
		t.Fatal(err)
	}

	serving := make(chan struct{})
	f.svc = NewService(Settings{
		Invoker: f.fn, Clock: f.clock,
		WaitServing: func(ctx context.Context) error {
			select {
			case <-serving:
				return nil
			case <-ctx.Done():
				return fmt.Errorf("not serving: %w", ctx.Err())
			}
		},
	})(&gas.NopLogger{}, f.store)
	if err := f.svc.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.svc.Close(context.Background()) })

	time.Sleep(50 * time.Millisecond)
	if got := f.fn.invoked(); len(got) != 0 {
		t.Fatalf("steps = %v before the server serves", got)
	}
	close(serving)
	f.settled(t)
	if got := f.fn.invoked(); !slices.Equal(got, steps) {
		t.Fatalf("steps = %v, want %v", got, steps)
	}
}

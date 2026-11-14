// Package rotation rotates secrets in the background, as Secrets Manager
// rotates a secret with a Lambda rotation function ("Rotation by Lambda
// function", Secrets Manager User Guide): it invokes the function once for
// each of the four steps, createSecret, setSecret, testSecret and
// finishSecret, as the service principal secretsmanager.amazonaws.com,
// through the functions service's service-invoke endpoint, and keeps the
// state of each rotation in the secret's record (contracts.RotationStore).
//
// A rotation starts when RotateSecret asks for one, and when a secret's
// rotation window opens (the scheduler). The runs are goroutines of the
// service, from Init to Close: Close stops them and waits, and leaves each
// run in the store as it was, which the next Init resumes, so a restart
// never leaves a rotation stuck in progress.
package rotation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/contracts"
)

// ServicePrincipal is the service principal rotation functions are invoked
// as, Secrets Manager's, which a function policy must allow
// lambda:InvokeFunction ("Set up automatic rotation using the AWS CLI",
// Secrets Manager User Guide).
const ServicePrincipal = "secretsmanager.amazonaws.com"

// The steps of a rotation, in the order they are invoked, as the event's
// Step names them. The User Guide's "Rotation by Lambda function" spells
// them create_secret and so on, but the functions Secrets Manager provides
// ("Rotation function templates") compare Step with these, and so does
// every rotation function written from them.
var (
	steps     = []string{"createSecret", "setSecret", "testSecret", "finishSecret"}
	testSteps = []string{"testSecret"}
)

// The defaults of a Service's retry and scheduling. AWS documents only that
// "If any rotation step fails, Secrets Manager retries the entire rotation
// process multiple times during the open rotation windows" ("Rotation by
// Lambda function"), so the numbers are this service's.
const (
	// maxAttempts is how many times a run is tried, the first included.
	maxAttempts = 3
	// retryDelay is the wait between a failed attempt and the next.
	retryDelay = time.Minute
	// checkInterval is how often the scheduler looks for windows that
	// have opened, on the service's clock.
	checkInterval = time.Minute
)

// Clock is the time the service reads and waits on: the system's, or a
// test's, which advances when the test says so.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time                         { return time.Now() }
func (systemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// SystemClock is the system's clock.
var SystemClock Clock = systemClock{}

// StepResult is what one step's invocation returned. FunctionError is set
// when the function failed, Payload then being its error document.
type StepResult struct {
	RequestID     string
	FunctionError string
	Payload       []byte
}

// Invoker invokes a rotation function for one step, as ServicePrincipal, for
// the secret secretARN: the functions service's service-invoke endpoint
// (NewFunctionsInvoker), or a test's.
type Invoker interface {
	Invoke(
		ctx context.Context,
		function string,
		event []byte,
		secretARN string,
	) (*StepResult, error)
}

// Settings configures a Service. Without an Invoker rotation is not served:
// Available is false, and nothing is scheduled or resumed. A nil Clock is
// SystemClock.
//
// WaitServing, when set, returns once the server serves, or with ctx's
// error. No rotation invokes a step before it has returned: a rotation
// resumed at startup would otherwise invoke its function before the server
// listens, and the function's calls back would be refused.
type Settings struct {
	Invoker     Invoker
	Clock       Clock
	WaitServing func(ctx context.Context) error
}

// Service runs rotations.
type Service struct {
	logger  gas.Logger
	store   contracts.SecretsProvider
	invoker Invoker
	clock   Clock
	runs    *runner
	// waitServing is Settings.WaitServing.
	waitServing func(ctx context.Context) error

	maxAttempts   int
	retryDelay    time.Duration
	checkInterval time.Duration
}

var (
	_ contracts.Rotations = (*Service)(nil)
	_ gas.Service         = (*Service)(nil)
)

// NewService returns the constructor gas uses to build a Service from
// settings, rotating the secrets of store.
func NewService(settings Settings) func(gas.Logger, contracts.SecretsProvider) *Service {
	return func(logger gas.Logger, store contracts.SecretsProvider) *Service {
		clock := settings.Clock
		if clock == nil {
			clock = SystemClock
		}
		return &Service{
			logger:        logger.With().Str("service", serviceName).Logger(),
			store:         store,
			invoker:       settings.Invoker,
			clock:         clock,
			runs:          newRunner(),
			waitServing:   settings.WaitServing,
			maxAttempts:   maxAttempts,
			retryDelay:    retryDelay,
			checkInterval: checkInterval,
		}
	}
}

const serviceName = "tule/services/rotation"

// Name identifies the service to gas.
func (s *Service) Name() string {
	return serviceName
}

// Available reports whether rotation is served.
func (s *Service) Available() bool {
	return s.invoker != nil
}

// Init starts the runs: it resumes every run the store holds, each at the
// attempt it was at, and starts the scheduler. Without an invoker it starts
// nothing. gas's RestartService calls it again after Close, which starts
// them over. Every run waits for the server to serve before its first step
// (Settings.WaitServing).
func (s *Service) Init(ctx context.Context) error {
	s.runs.begin(s.waitServing) //nolint:contextcheck // the wait lives as long as the service
	if !s.Available() {
		return nil
	}
	runs, err := s.store.RotationRuns(contracts.Unchecked(ctx))
	if err != nil {
		s.runs.stopNow()
		return fmt.Errorf("%s: the rotations to resume: %w", s.Name(), err)
	}
	for _, run := range runs {
		s.logger.Info("resuming a rotation").Str("secret", run.SecretARN).
			Str("version_id", run.Token).Int("attempt", run.Attempt).Send()
		s.launch(run) //nolint:contextcheck // a run lives as long as the service, not Init
	}
	s.runs.goBackground(s.schedule) //nolint:contextcheck // as above
	return nil
}

// Close stops every run and the scheduler, and waits for them, up to ctx's
// end. The runs stay in the store, for the next Init to resume.
func (s *Service) Close(ctx context.Context) error {
	if err := s.runs.stop(ctx); err != nil {
		return fmt.Errorf("%s: %w", s.Name(), err)
	}
	return nil
}

// errUnavailable is a rotation asked of a service with no invoker, which
// the module answers 501 before it gets here.
var errUnavailable = errors.New("rotation: no functions endpoint is configured")

// errStopped is a rotation asked of a service that is closed.
var errStopped = errors.New("rotation: the service is closed; no rotation can start")

// Rotate starts a rotation and runs it in the background.
func (s *Service) Rotate(
	ctx context.Context,
	in contracts.StartRotationInput,
) (*contracts.RotationStarted, error) {
	if !s.Available() {
		return nil, errUnavailable
	}
	if !s.runs.running() {
		return nil, errStopped
	}
	in.Now = s.clock.Now()
	out, err := s.store.StartRotation(ctx, in)
	if err != nil {
		return nil, err
	}
	if out.Run != nil {
		s.launch(*out.Run) //nolint:contextcheck // a run outlives the request that starts it
	}
	return out, nil
}

// Cancel turns rotation off and stops the run it ended, if any. Only that
// run is stopped: one a concurrent RotateSecret started after it, which
// has another ID, runs on.
func (s *Service) Cancel(ctx context.Context, secretID string) (*contracts.SecretVersion, error) {
	out, err := s.store.CancelRotation(ctx, secretID)
	if err != nil {
		return nil, err
	}
	s.runs.cancel(out.RunID)
	return &out.SecretVersion, nil
}

// StopRun stops the goroutine of the run runID, which the store ended.
func (s *Service) StopRun(runID string) {
	s.runs.cancel(runID)
}

// launch runs run on a goroutine of its own, keyed by its ID.
func (s *Service) launch(run contracts.RotationRun) {
	s.runs.launch(run.ID, func(ctx context.Context) { s.run(ctx, run) })
}

// schedule starts the runs of the windows that open, every checkInterval,
// until ctx ends.
func (s *Service) schedule(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.clock.After(s.checkInterval):
		}
		runs, err := s.store.StartDueRotations(contracts.Unchecked(ctx), s.clock.Now())
		if err != nil {
			s.logger.Error("failed to start the scheduled rotations").Err("error", err).Send()
		}
		for _, run := range runs {
			s.logger.Info("starting a scheduled rotation").Str("secret", run.SecretARN).
				Str("version_id", run.Token).Send()
			//nolint:contextcheck // each run has its own lifetime, under the service's
			s.launch(run)
		}
	}
}

// run runs the attempts of run until the store has recorded it over, or
// ctx ends. ctx ends only when the service closes, which leaves the run in
// the store for the next start to resume, or when Cancel or StopRun stops
// it, once the store has ended it: no run is left in the store with
// nothing running it.
func (s *Service) run(ctx context.Context, run contracts.RotationRun) {
	if !s.runs.awaitServing(ctx) {
		return
	}
	for {
		if !s.sleepUntil(ctx, run.RetryAt) {
			return
		}
		failure := s.attempt(ctx, run)
		if ctx.Err() != nil {
			return
		}
		out, ok := s.record(ctx, run, failure)
		if !ok {
			return
		}
		s.report(run, failure, out)
		if out.Retry == nil {
			return
		}
		run = *out.Retry
	}
}

// sleepUntil waits on the clock until t, a zero t not at all, and reports
// whether ctx is still live.
func (s *Service) sleepUntil(ctx context.Context, t time.Time) bool {
	if wait := t.Sub(s.clock.Now()); !t.IsZero() && wait > 0 {
		select {
		case <-ctx.Done():
			return false
		case <-s.clock.After(wait):
		}
	}
	return ctx.Err() == nil
}

// record records how an attempt ended. A failure to record is retried
// every retryDelay until it succeeds or ctx ends, so the run is never left
// in the store without its goroutine.
func (s *Service) record(
	ctx context.Context,
	run contracts.RotationRun,
	failure error,
) (*contracts.RotationOutcome, bool) {
	for {
		out, err := s.store.EndRotationAttempt(contracts.Unchecked(ctx), contracts.EndRotationInput{
			Now:         s.clock.Now(),
			SecretARN:   run.SecretARN,
			RunID:       run.ID,
			RetryDelay:  s.retryDelay,
			MaxAttempts: s.maxAttempts,
			Failed:      failure != nil,
		})
		if err == nil {
			return out, true
		}
		s.logger.Error("failed to record a rotation attempt; recording it again").
			Str("secret", run.SecretARN).Str("version_id", run.Token).Err("error", err).Send()
		if !s.sleepUntil(ctx, s.clock.Now().Add(s.retryDelay)) {
			return nil, false
		}
	}
}

// report logs how an attempt ended.
func (s *Service) report(run contracts.RotationRun, failure error, out *contracts.RotationOutcome) {
	if out.Unmoved {
		failure = errors.New("finishSecret succeeded but left AWSCURRENT off the pending version")
	}
	switch {
	case out.Gone:
		s.logger.Info("rotation ended: it was canceled, replaced or its secret deleted").
			Str("secret", run.SecretARN).Str("version_id", run.Token).Send()
	case failure == nil && run.TestOnly:
		s.logger.Info("rotation test succeeded").Str("secret", run.SecretARN).
			Str("version_id", run.Token).Send()
	case failure == nil:
		s.logger.Info("rotation succeeded").Str("secret", run.SecretARN).
			Str("version_id", run.Token).Send()
	case out.Retry != nil:
		s.logger.Warn("rotation attempt failed; it will be retried").Str("secret", run.SecretARN).
			Str("version_id", run.Token).Int("attempt", run.Attempt).
			Str("retry_at", out.Retry.RetryAt.Format(time.RFC3339)).Err("error", failure).Send()
	default:
		s.logger.Error("rotation failed").Str("secret", run.SecretARN).
			Str("version_id", run.Token).Int("attempt", run.Attempt).Err("error", failure).Send()
	}
}

// errGone is an attempt stopped because its run is no longer the secret's.
var errGone = errors.New("the rotation is no longer the secret's")

// stepEvent is the event a rotation function is invoked with ("Rotation by
// Lambda function"). RotationToken, which Secrets Manager sends for a
// function that calls it through an assumed role or from another account,
// is not sent: this service has no use for one, and ignores it on
// PutSecretValue.
type stepEvent struct {
	Step               string `json:"Step"`
	SecretID           string `json:"SecretId"`
	ClientRequestToken string `json:"ClientRequestToken"`
}

// maxErrorPayload bounds how much of a failed function's error document an
// attempt's error carries into the log.
const maxErrorPayload = 1024

// attempt invokes each step of run in turn, synchronously, and returns the
// first failure: an invocation that could not be made or was refused, or a
// function that failed. Before each step it checks the run is still the
// secret's, so a canceled run invokes no further step.
func (s *Service) attempt(ctx context.Context, run contracts.RotationRun) error {
	todo := steps
	if run.TestOnly {
		todo = testSteps
	}
	for _, step := range todo {
		running, err := s.store.RotationRunning(contracts.Unchecked(ctx), run.SecretARN, run.ID)
		if err != nil {
			return fmt.Errorf("%s: %w", step, err)
		}
		if !running {
			return errGone
		}
		event, err := json.Marshal(stepEvent{
			Step: step, SecretID: run.SecretARN, ClientRequestToken: run.Token,
		})
		if err != nil {
			return fmt.Errorf("%s: encode the event: %w", step, err)
		}
		res, err := s.invoker.Invoke(ctx, run.LambdaARN, event, run.SecretARN)
		if err != nil {
			return fmt.Errorf("%s: invoke %s: %w", step, run.LambdaARN, err)
		}
		if res.FunctionError != "" {
			payload := res.Payload
			if len(payload) > maxErrorPayload {
				payload = payload[:maxErrorPayload]
			}
			return fmt.Errorf("%s: %s failed (%s, request %s): %s",
				step, run.LambdaARN, res.FunctionError, res.RequestID, payload)
		}
	}
	return nil
}

// runner holds the goroutines of the runs and the scheduler, from begin to
// stop. Each run is keyed by its ID, so Cancel and StopRun stop that run and
// no other. serving is closed once the server serves.
type runner struct {
	ctx     context.Context //nolint:containedctx // the goroutines' lifetime, ended by stop
	stopFn  context.CancelFunc
	active  map[string]*activeRun
	serving chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
}

type activeRun struct {
	cancel context.CancelFunc
}

// newRunner returns a runner that is stopped until begin.
func newRunner() *runner {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return &runner{ctx: ctx, stopFn: cancel, active: map[string]*activeRun{}}
}

// begin starts the runner's lifetime. With waitServing, the runs wait for
// it to return before they invoke anything; it is waited for on a goroutine
// stop waits for, and stop ends it.
func (r *runner) begin(waitServing func(ctx context.Context) error) {
	r.mu.Lock()
	r.stopFn()
	r.ctx, r.stopFn = context.WithCancel(context.Background())
	serving := make(chan struct{})
	r.serving = serving
	r.mu.Unlock()
	if waitServing == nil {
		close(serving)
		return
	}
	r.goBackground(func(ctx context.Context) {
		if waitServing(ctx) == nil {
			close(serving)
		}
	})
}

// awaitServing waits until the server serves, and reports whether it does
// before ctx ends.
func (r *runner) awaitServing(ctx context.Context) bool {
	r.mu.Lock()
	serving := r.serving
	r.mu.Unlock()
	select {
	case <-serving:
		return ctx.Err() == nil
	case <-ctx.Done():
		return false
	}
}

func (r *runner) running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ctx.Err() == nil
}

// goBackground runs fn on a goroutine stop waits for.
func (r *runner) goBackground(fn func(ctx context.Context)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx.Err() != nil {
		return
	}
	r.wg.Add(1)
	ctx := r.ctx
	go func() {
		defer r.wg.Done()
		fn(ctx)
	}()
}

// launch runs fn for the run key. Once stopped it starts nothing: the run
// stays in the store for the next begin.
func (r *runner) launch(key string, fn func(ctx context.Context)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.ctx)
	a := &activeRun{cancel: cancel}
	r.active[key] = a
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() {
			cancel()
			r.mu.Lock()
			if r.active[key] == a {
				delete(r.active, key)
			}
			r.mu.Unlock()
		}()
		fn(ctx)
	}()
}

// cancel stops the run of key, if one is running.
func (r *runner) cancel(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.active[key]; ok {
		a.cancel()
		delete(r.active, key)
	}
}

// size is how many runs are running.
func (r *runner) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.active)
}

// stopNow stops the goroutines without waiting, for an Init that fails.
func (r *runner) stopNow() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopFn()
}

// stop stops every goroutine and waits for them, up to ctx's end.
func (r *runner) stop(ctx context.Context) error {
	r.stopNow()
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		select {
		case <-done:
			return nil
		default:
			return fmt.Errorf("the rotations did not stop in time: %w", ctx.Err())
		}
	}
}

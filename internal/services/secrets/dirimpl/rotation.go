package dirimpl

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/schedule"
)

// recordRotation is a secret's rotation configuration and the rotation that
// runs on it, kept in the secret's record so a restart finds both.
//
// ConfiguredDate is when rotation was last turned on and LastRotatedDate
// when a rotation last succeeded: the next window is the first after the
// latest of these and of the current version's creation (see nextWindow).
// SkipThrough is when the last scheduled rotation failed for good: the
// scheduler starts no window that began at or before it, so it tries again
// at the first window after it, without moving the schedule itself.
type recordRotation struct {
	ConfiguredDate  time.Time    `json:"configuredDate"`
	LastRotatedDate time.Time    `json:"lastRotatedDate,omitzero"`
	SkipThrough     time.Time    `json:"skipThrough,omitzero"`
	Rules           *recordRules `json:"rules,omitempty"`
	Run             *recordRun   `json:"run,omitempty"`
	LambdaARN       string       `json:"lambdaArn"`
	Enabled         bool         `json:"enabled"`
}

// recordRules are the rotation rules as RotateSecret set them.
type recordRules struct {
	ScheduleExpression     string `json:"scheduleExpression,omitempty"`
	Duration               string `json:"duration,omitempty"`
	AutomaticallyAfterDays int64  `json:"automaticallyAfterDays,omitempty"`
}

// recordRun is the rotation running on a secret (contracts.RotationRun). ID
// is unique to the run, so a run is never mistaken for a later one of the
// same secret that reuses its token.
type recordRun struct {
	RetryAt   time.Time `json:"retryAt,omitzero"`
	WindowEnd time.Time `json:"windowEnd,omitzero"`
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	Attempt   int       `json:"attempt"`
	TestOnly  bool      `json:"testOnly,omitempty"`
}

func (r *recordRules) rules() schedule.Rules {
	return schedule.Rules{
		AutomaticallyAfterDays: r.AutomaticallyAfterDays,
		ScheduleExpression:     r.ScheduleExpression,
		Duration:               r.Duration,
	}
}

func (r *record) runOf() contracts.RotationRun {
	run := r.Rotation.Run
	return contracts.RotationRun{
		ID:        run.ID,
		SecretARN: r.ARN,
		LambdaARN: r.Rotation.LambdaARN,
		Token:     run.Token,
		Attempt:   run.Attempt,
		TestOnly:  run.TestOnly,
		RetryAt:   run.RetryAt,
		WindowEnd: run.WindowEnd,
	}
}

// rotationDetail reports the secret's rotation configuration, nil when it
// was never configured. The dates are left out while rotation is off, as
// DescribeSecret leaves them out ("If the secret isn't configured for
// rotation or rotation has been disabled, Secrets Manager returns null").
// Stored rules that no longer parse give no NextRotationDate here; the
// scheduler reports them (StartDueRotations).
func (r *record) rotationDetail() *contracts.RotationDetail {
	rot := r.Rotation
	if rot == nil {
		return nil
	}
	d := &contracts.RotationDetail{Enabled: rot.Enabled, LambdaARN: rot.LambdaARN}
	if rot.Rules != nil {
		rules := rot.Rules.rules()
		d.Rules = &rules
	}
	if !rot.Enabled {
		return d
	}
	d.LastRotatedDate = rot.LastRotatedDate
	// Counted from the last rotation alone, so after a failed rotation the
	// date may be in the past, as DescribeSecret's may ("If rotation is
	// unsuccessful, this date may be in the past").
	if _, end, ok, err := r.nextWindow(); ok && err == nil {
		d.NextRotationDate = end
	}
	return d
}

// nextWindow returns the next rotation window of an enabled secret with
// rules: the first after the last rotation, counting a value stored by hand
// as one ("Manually updating the secret value by calling PutSecretValue or
// UpdateSecret is considered a valid rotation", RotationRulesType), and the
// time rotation was turned on. A failed rotation does not move it. ok is
// false for a secret with no rules.
func (r *record) nextWindow() (start, end time.Time, ok bool, err error) {
	sched, err := r.schedule()
	if sched == nil || err != nil {
		return time.Time{}, time.Time{}, false, err
	}
	rot := r.Rotation
	base := rot.ConfiguredDate
	if rot.LastRotatedDate.After(base) {
		base = rot.LastRotatedDate
	}
	if cur := r.byStage(contracts.StageCurrent); cur != nil && cur.CreatedDate.After(base) {
		base = cur.CreatedDate
	}
	start, end, ok = sched.Next(base)
	return start, end, ok, nil
}

// dueWindow is the window the scheduler is to rotate in next: nextWindow,
// unless that one began at or before the last scheduled rotation that
// failed for good, and then the first window after that failure, so a
// failed window is neither retried past its attempts nor skipped beyond the
// next.
func (r *record) dueWindow() (start, end time.Time, ok bool, err error) {
	start, end, ok, err = r.nextWindow()
	skip := r.Rotation.SkipThrough
	if !ok || err != nil || skip.IsZero() || start.After(skip) {
		return start, end, ok, err
	}
	sched, err := r.schedule()
	if err != nil {
		return time.Time{}, time.Time{}, false, err
	}
	start, end, ok = sched.Next(skip)
	return start, end, ok, nil
}

// schedule parses the stored rules, nil for a secret with none.
func (r *record) schedule() (*schedule.Schedule, error) {
	rot := r.Rotation
	if rot == nil || rot.Rules == nil {
		return nil, nil //nolint:nilnil // no rules is not an error
	}
	sched, err := schedule.Parse(rot.Rules.rules())
	if err != nil {
		return nil, fmt.Errorf("the stored rotation rules of %s: %w", r.Name, err)
	}
	return sched, nil
}

// endRun ends the run on the secret, if any, and returns its ID.
func (r *record) endRun() string {
	if r.Rotation == nil || r.Rotation.Run == nil {
		return ""
	}
	id := r.Rotation.Run.ID
	r.Rotation.Run = nil
	return id
}

// currentIs reports whether AWSCURRENT is on the version versionID.
func (r *record) currentIs(versionID string) bool {
	cur := r.byStage(contracts.StageCurrent)
	return cur != nil && cur.VersionID == versionID
}

// failRun records a failed attempt of the secret's run, and returns the
// next attempt, or nil when the run is over (see EndRotationAttempt).
func (r *record) failRun(in contracts.EndRotationInput) *contracts.RotationRun {
	rot, run := r.Rotation, r.Rotation.Run
	retryAt := in.Now.Add(in.RetryDelay)
	if run.Attempt < in.MaxAttempts && (run.WindowEnd.IsZero() || retryAt.Before(run.WindowEnd)) {
		run.Attempt++
		run.RetryAt = retryAt.UTC()
		retry := r.runOf()
		return &retry
	}
	if !run.WindowEnd.IsZero() {
		rot.SkipThrough = in.Now.UTC()
	}
	rot.Run = nil
	return nil
}

// pendingApart returns the version holding AWSPENDING when it is not the one
// holding AWSCURRENT: a rotation that has not completed. When a rotation
// succeeds, AWSPENDING is left on the AWSCURRENT version, or on none (API
// reference, RotateSecret).
func (r *record) pendingApart() *recordVersion {
	pending := r.byStage(contracts.StagePending)
	if pending == nil || slices.Contains(pending.Stages, contracts.StageCurrent) {
		return nil
	}
	return pending
}

// beginRun puts a new run of token on the secret, with an ID of its own,
// creating the version without a value that the rotation function fills,
// holding AWSPENDING, unless the version exists.
func (s *Service) beginRun(rec *record, token string, testOnly bool, windowEnd time.Time) error {
	id, err := newVersionID()
	if err != nil {
		return fmt.Errorf("failed to generate a rotation ID: %w", err)
	}
	if rec.byID(token) == nil {
		rec.addVersion(recordVersion{VersionID: token, CreatedDate: s.now().UTC()},
			[]string{contracts.StagePending})
	}
	rec.Rotation.Run = &recordRun{
		ID: id, Token: token, Attempt: 1, TestOnly: testOnly, WindowEnd: windowEnd,
	}
	return nil
}

// StartRotation configures rotation on a secret and starts a run on it.
//
// A secret is "in progress", and refused with ErrRotationInProgress, while
// a run is on it or its AWSPENDING version is not its AWSCURRENT one: "If
// the AWSPENDING staging label is present but not attached to the same
// version as AWSCURRENT, then any later invocation of RotateSecret assumes
// that a previous rotation request is still in progress and returns an
// error" (API reference, RotateSecret). A request whose token is the
// running run's, or the AWSCURRENT version's, repeats a request already
// served, as an SDK retry does, and starts nothing; one whose token is the
// AWSPENDING version's starts that rotation again, to the same version.
func (s *Service) StartRotation(
	ctx context.Context,
	in contracts.StartRotationInput,
) (*contracts.RotationStarted, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.resolveLive(ctx, in.SecretID)
	if err != nil {
		return nil, err
	}
	if rec.Rotation == nil {
		rec.Rotation = &recordRotation{}
	}
	rot := rec.Rotation
	if in.LambdaARN == "" && rot.LambdaARN == "" {
		return nil, fmt.Errorf("%w: %s", contracts.ErrNoRotationFunction, rec.Name)
	}

	token, repeat, err := rotationToken(rec, in.Token)
	switch {
	case err != nil:
		return nil, err
	case repeat:
		return &contracts.RotationStarted{SecretRef: rec.ref(), VersionID: token}, nil
	}

	rot.configure(in)
	if err = s.beginRun(rec, token, in.TestOnly, time.Time{}); err != nil {
		return nil, err
	}
	rec.LastChangedDate = s.now().UTC()

	if err = s.write(rec); err != nil {
		return nil, err
	}
	run := rec.runOf()
	return &contracts.RotationStarted{Run: &run, SecretRef: rec.ref(), VersionID: token}, nil
}

// rotationToken checks a request's token against the secret's rotation
// state (see StartRotation). It returns the token to rotate to, generated
// when the request has none, and repeat for a request already served.
func rotationToken(rec *record, token string) (string, bool, error) {
	if run := rec.Rotation.Run; run != nil {
		if token != "" && token == run.Token {
			return token, true, nil
		}
		return "", false, fmt.Errorf("%w: %s", contracts.ErrRotationInProgress, rec.Name)
	}
	if pending := rec.pendingApart(); pending != nil {
		if token != pending.VersionID {
			return "", false, fmt.Errorf("%w: %s", contracts.ErrRotationInProgress, rec.Name)
		}
		return token, false, nil
	}
	if token == "" {
		generated, err := newVersionID()
		return generated, false, err
	}
	if v := rec.byID(token); v != nil {
		if slices.Contains(v.Stages, contracts.StageCurrent) {
			return token, true, nil
		}
		return "", false, fmt.Errorf("%w: version %s of %s",
			contracts.ErrVersionExists, token, rec.Name)
	}
	return token, false, nil
}

// configure applies a request's configuration: its function and rules
// replace the stored ones, and rotation turns on, counting the schedule
// from now when it was off.
func (rot *recordRotation) configure(in contracts.StartRotationInput) {
	if in.LambdaARN != "" {
		rot.LambdaARN = in.LambdaARN
	}
	if in.Rules != nil {
		rot.Rules = &recordRules{
			AutomaticallyAfterDays: in.Rules.AutomaticallyAfterDays,
			ScheduleExpression:     in.Rules.ScheduleExpression,
			Duration:               in.Rules.Duration,
		}
	}
	if !rot.Enabled {
		rot.Enabled = true
		rot.ConfiguredDate = in.Now.UTC()
		rot.SkipThrough = time.Time{}
	}
}

// CancelRotation turns rotation off and ends the run on the secret. The
// rules and function stay, as DescribeSecret shows "the previous rotation
// schedule and rotation function" of a secret whose rotation was turned
// off. The AWSPENDING version is left as it is, for the caller to clean up
// ("You might need to remove the staging label AWSPENDING from the
// partially created version", API reference, CancelRotateSecret), and is
// returned. A secret never configured for rotation is left unchanged.
func (s *Service) CancelRotation(
	ctx context.Context,
	secretID string,
) (*contracts.RotationCanceled, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.resolveLive(ctx, secretID)
	if err != nil {
		return nil, err
	}
	out := &contracts.RotationCanceled{SecretVersion: contracts.SecretVersion{SecretRef: rec.ref()}}
	if pending := rec.pendingApart(); pending != nil {
		out.VersionID = pending.VersionID
	}
	if rec.Rotation == nil {
		return out, nil
	}

	out.RunID = rec.endRun()
	rec.Rotation.Enabled = false
	rec.LastChangedDate = s.now().UTC()
	if err = s.write(rec); err != nil {
		return nil, err
	}
	return out, nil
}

// StartDueRotations starts a run on every enabled secret whose next window
// has started, with no run on it. A secret whose AWSPENDING version is apart
// from AWSCURRENT, left by a rotation that failed, is rotated to that
// version again. A window that ended before now, missed while the service
// was down, is rotated once at once, and not retried.
func (s *Service) StartDueRotations(
	_ context.Context,
	now time.Time,
) ([]contracts.RotationRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	recs, err := s.all()
	if err != nil {
		return nil, err
	}

	var (
		runs []contracts.RotationRun
		errs []error
	)
	for _, rec := range recs {
		started, sErr := s.startDue(rec, now)
		if sErr != nil {
			errs = append(errs, sErr)
		}
		if started {
			runs = append(runs, rec.runOf())
		}
	}
	return runs, errors.Join(errs...)
}

// startDue starts a scheduled run on rec, and stores it, when its window
// has opened at now.
func (s *Service) startDue(rec *record, now time.Time) (bool, error) {
	rot := rec.Rotation
	if rec.deleted() || rot == nil || !rot.Enabled || rot.Run != nil {
		return false, nil
	}
	start, end, ok, err := rec.dueWindow()
	if err != nil || !ok || now.Before(start) {
		return false, err
	}
	if err = s.beginScheduledRun(rec, end); err != nil {
		return false, err
	}
	return true, nil
}

// beginScheduledRun puts a scheduled run on rec, for the window ending at
// end, and stores it.
func (s *Service) beginScheduledRun(rec *record, end time.Time) error {
	token, err := scheduledToken(rec)
	if err != nil {
		return err
	}
	if err = s.beginRun(rec, token, false, end); err != nil {
		return err
	}
	return s.write(rec)
}

// scheduledToken is the version a scheduled run rotates to: the AWSPENDING
// version a failed rotation left apart from AWSCURRENT, or a new one.
func scheduledToken(rec *record) (string, error) {
	if pending := rec.pendingApart(); pending != nil {
		return pending.VersionID, nil
	}
	return newVersionID()
}

// RotationRuns returns the run of every secret that has one.
func (s *Service) RotationRuns(context.Context) ([]contracts.RotationRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	recs, err := s.all()
	if err != nil {
		return nil, err
	}
	var runs []contracts.RotationRun
	for _, rec := range recs {
		if rec.Rotation != nil && rec.Rotation.Run != nil && !rec.deleted() {
			runs = append(runs, rec.runOf())
		}
	}
	return runs, nil
}

// RotationRunning reports whether the run of token is still on the secret
// secretARN.
func (s *Service) RotationRunning(_ context.Context, secretARN, runID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.runOn(secretARN, runID)
	if err != nil {
		return false, err
	}
	return rec != nil, nil
}

// runOn returns the secret secretARN when the run runID is on it, and nil
// when it is not: the secret is gone or scheduled for deletion, or the run
// was canceled or replaced.
func (s *Service) runOn(secretARN, runID string) (*record, error) {
	rec, err := s.lookup(secretARN)
	switch {
	case errorIsNotFound(err):
		return nil, nil
	case err != nil:
		return nil, err
	}
	if rec.deleted() || rec.Rotation == nil || rec.Rotation.Run == nil ||
		rec.Rotation.Run.ID != runID {
		return nil, nil
	}
	return rec, nil
}

// EndRotationAttempt records how an attempt ended.
//
// A test run (TestOnly) is over after one attempt, and AWSPENDING comes off
// its version: "This test creates an AWSPENDING version of the secret and
// then removes it" (API reference, RotateSecret RotateImmediately). Any
// other attempt that did not fail succeeded only if AWSCURRENT is on the
// run's version; a success records LastRotatedDate. A failed attempt is
// retried while the run has attempts left and, scheduled, its window is
// open; a scheduled run that runs out of either moves the next window past
// its own. The version and its AWSPENDING stay, so the next rotation, by
// request with the same token or by schedule, rotates to it again.
func (s *Service) EndRotationAttempt(
	_ context.Context,
	in contracts.EndRotationInput,
) (*contracts.RotationOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.runOn(in.SecretARN, in.RunID)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return &contracts.RotationOutcome{Gone: true}, nil
	}
	rot, run := rec.Rotation, rec.Rotation.Run
	out := &contracts.RotationOutcome{}

	switch {
	case run.TestOnly:
		if v := rec.byID(run.Token); v != nil && slices.Contains(v.Stages, contracts.StagePending) {
			rec.detachStage(contracts.StagePending)
			rec.LastChangedDate = s.now().UTC()
		}
		rot.Run = nil
	case !in.Failed && rec.currentIs(run.Token):
		rot.Run = nil
		rot.LastRotatedDate = in.Now.UTC()
	default:
		out.Unmoved = !in.Failed
		out.Retry = rec.failRun(in)
	}

	if err = s.write(rec); err != nil {
		return nil, err
	}
	return out, nil
}

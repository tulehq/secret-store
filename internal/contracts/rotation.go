package contracts

import (
	"context"
	"errors"
	"time"

	"tule.dev/secret-store/internal/schedule"
)

var (
	// ErrRotationInProgress is returned by StartRotation for a secret whose
	// AWSPENDING version is not its AWSCURRENT one, or that a rotation is
	// running on, with another client request token.
	ErrRotationInProgress = errors.New("secrets: a previous rotation isn't complete")

	// ErrNoRotationFunction is returned by StartRotation for a secret that
	// has no rotation function and a request that names none.
	ErrNoRotationFunction = errors.New(
		"secrets: no rotation function is associated with the secret",
	)
)

// RotationStore is the part of the secret store rotation works on: the
// rotation configuration of each secret, and the state of the rotation that
// runs on it, kept in the secret's own record so a restart finds it.
//
// StartRotation and CancelRotation act for a request and run its Check. The
// others are the rotation service's own, made with an Unchecked context.
type RotationStore interface {
	// StartRotation applies in's configuration and starts a rotation run
	// on the secret, creating the AWSPENDING version it rotates to (see
	// StartRotationInput).
	StartRotation(ctx context.Context, in StartRotationInput) (*RotationStarted, error)
	// CancelRotation turns rotation off, ends any run, and returns the
	// version that holds AWSPENDING apart from AWSCURRENT, if any, which it
	// leaves in place, and the ID of the run it ended, if any.
	CancelRotation(ctx context.Context, secretID string) (*RotationCanceled, error)
	// StartDueRotations starts a run on every secret whose next rotation
	// window has started at now and that no run is on. Stored rules that
	// no longer parse are reported in the error, beside the runs started.
	StartDueRotations(ctx context.Context, now time.Time) ([]RotationRun, error)
	// RotationRuns returns every run the store holds, for the service to
	// resume when it starts.
	RotationRuns(ctx context.Context) ([]RotationRun, error)
	// RotationRunning reports whether the run runID is still the one on the
	// secret secretARN: not canceled, replaced, or ended by the secret's
	// deletion. A run is told by its ID, never by its token, which a later
	// run of the same secret may reuse.
	RotationRunning(ctx context.Context, secretARN, runID string) (bool, error)
	// EndRotationAttempt records how an attempt of a run ended (see
	// EndRotationInput).
	EndRotationAttempt(ctx context.Context, in EndRotationInput) (*RotationOutcome, error)
}

// RotationDetail is a secret's rotation configuration as DescribeSecret
// reports it. LastRotatedDate and NextRotationDate are zero while rotation is
// off, and NextRotationDate also without a schedule. Rules is nil when none
// were ever set.
type RotationDetail struct {
	LastRotatedDate  time.Time
	NextRotationDate time.Time
	Rules            *schedule.Rules
	LambdaARN        string
	Enabled          bool
}

// StartRotationInput configures rotation on a secret and starts a rotation.
// A nil Rules keeps the stored rules, and an empty LambdaARN the stored
// function. Token, from the request's client request token, is the ID of the
// AWSPENDING version the run rotates to; an empty one is generated. With
// TestOnly the run only invokes testSecret, and then takes AWSPENDING off
// the version, as RotateSecret with RotateImmediately false does. Now is
// when the request was made, on the rotation service's clock.
type StartRotationInput struct {
	Now       time.Time
	Rules     *schedule.Rules
	SecretID  string
	LambdaARN string
	Token     string
	TestOnly  bool
}

// RotationStarted is StartRotation's answer: the secret, the version the
// rotation is to, and the run to launch, nil when the request repeats one
// already running or done, which starts nothing.
type RotationStarted struct {
	Run *RotationRun
	SecretRef
	VersionID string
}

// RotationRun is one rotation of a secret: its ID, unique to the run, its
// token, the AWSPENDING version it rotates to, the function that rotates
// it, and the attempt it is at.
// RetryAt is when the attempt is to start, zero for at once. WindowEnd is
// the end of the rotation window of a scheduled run, past which it is not
// retried, and zero for a run a request started.
type RotationRun struct {
	RetryAt   time.Time
	WindowEnd time.Time
	ID        string
	SecretARN string
	LambdaARN string
	Token     string
	Attempt   int
	TestOnly  bool
}

// EndRotationInput reports an attempt of the run RunID on the secret
// SecretARN. Failed says one of its steps failed. An attempt that did not
// fail succeeded only if AWSCURRENT is now on the run's version, as
// finishSecret is to leave it. A failed attempt is retried RetryDelay after
// Now, up to MaxAttempts attempts, and for a scheduled run only within its
// window.
type EndRotationInput struct {
	Now         time.Time
	SecretARN   string
	RunID       string
	RetryDelay  time.Duration
	MaxAttempts int
	Failed      bool
}

// RotationOutcome is what EndRotationAttempt made of an attempt. Retry is
// the run's next attempt, nil when the run is over. Unmoved says the attempt
// reported success but left AWSCURRENT off the run's version. Gone says the
// run was no longer the secret's, canceled, replaced or deleted, so nothing
// was recorded.
type RotationOutcome struct {
	Retry   *RotationRun
	Unmoved bool
	Gone    bool
}

// Rotations is the rotation service the API's RotateSecret and
// CancelRotateSecret are served by.
type Rotations interface {
	// Available reports whether rotation is served: a functions endpoint
	// is configured to invoke rotation functions through.
	Available() bool
	// Rotate starts a rotation, as StartRotation, and runs it in the
	// background. in.Now is set by the service.
	Rotate(ctx context.Context, in StartRotationInput) (*RotationStarted, error)
	// Cancel cancels rotation, as CancelRotation, and stops the run it
	// ended.
	Cancel(ctx context.Context, secretID string) (*SecretVersion, error)
	// StopRun stops the goroutine of the run runID, which the store has
	// already ended, as DeleteSecret ends one. An unknown ID stops nothing.
	StopRun(runID string)
}

// RotationCanceled is CancelRotation's answer: the secret and the version
// holding AWSPENDING apart from AWSCURRENT, if any, and RunID, the run it
// ended, empty when none was running.
type RotationCanceled struct {
	RunID string
	SecretVersion
}

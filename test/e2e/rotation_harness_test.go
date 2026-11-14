//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
)

// The rotation tests run the whole stack: identity, a real functions
// service built from its checkout, and secret-store pointed at both. The
// rotation function is testdata/rotator, built for linux on the host's
// architecture and wrapped in an image built FROM scratch, so nothing is
// pulled. Its containers reach secret-store through the Docker host, as
// host.docker.internal, so secret-store listens where that name leads:
// the address functions binds its Runtime API to for the same reason
// (dockerHostAddress).

// functionsDirEnv names the functions checkout to build, for a layout where
// it is not secret-store's sibling.
const functionsDirEnv = "TULE_E2E_FUNCTIONS_DIR"

// runID tells this run's image apart from any other run's.
var runID = strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strconv.Itoa(os.Getpid())

// rotatorImage is the rotation function's image.
var rotatorImage = "tule-secret-store-e2e/rotator:" + runID

// rotatorBuild builds the image once, for the first test that needs it.
var rotatorBuild struct {
	err  error
	once sync.Once
	done bool
}

func TestMain(m *testing.M) {
	code := m.Run()
	if rotatorBuild.done {
		removeRotatorImage()
	}
	os.Exit(code)
}

// requireRotatorImage builds the rotator image, once.
func requireRotatorImage(t *testing.T) {
	t.Helper()
	rotatorBuild.once.Do(func() {
		rotatorBuild.done = true
		rotatorBuild.err = buildRotatorImage()
	})
	requireNoErr(t, rotatorBuild.err, "build the rotator image")
}

// buildRotatorImage builds testdata/rotator as a static linux binary, with
// lambda.norpc since it speaks only the Runtime API, and the image FROM
// scratch around it, never pulling. The function is a module of its own,
// so aws-lambda-go is not a requirement of secret-store.
func buildRotatorImage() error {
	dir, err := os.MkdirTemp("", "tule-secret-store-e2e-")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	//nolint:gosec // G204: go build of this suite's own testdata
	build := exec.Command("go", "build", "-tags", "lambda.norpc", "-trimpath",
		"-o", filepath.Join(dir, "bootstrap"), "./rotator")
	build.Dir = "testdata"
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, bErr := build.CombinedOutput(); bErr != nil {
		return fmt.Errorf("build the rotator: %w\n%s", bErr, out)
	}
	dockerfile := "FROM scratch\nCOPY bootstrap /bootstrap\nENTRYPOINT [\"/bootstrap\"]\n"
	if err = os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		return fmt.Errorf("Dockerfile: %w", err)
	}
	_, err = docker(context.Background(), "build", "--pull=false", "-q",
		"--label", "dev.tule.e2e.run="+runID, "-t", rotatorImage, dir)
	return err
}

// removeRotatorImage removes the containers left from the image, which the
// functions service removes itself when it stops, and the image.
func removeRotatorImage() {
	ctx := context.Background()
	ids, _ := docker(ctx, "ps", "-a", "-q", "--filter", "ancestor="+rotatorImage)
	if f := strings.Fields(ids); len(f) > 0 {
		fmt.Fprintf(os.Stderr, "e2e: removing %d containers left from %s\n", len(f), rotatorImage)
		_, _ = docker(ctx, append([]string{"rm", "-f"}, f...)...)
	}
	_, _ = docker(ctx, "rmi", "-f", rotatorImage)
}

// dockerHostAddress returns the address on the Docker host that the
// containers reach as host.docker.internal, as the functions service works
// it out for its Runtime API (functions' docker.Client.HostAddress, and its
// README's TULE_Functions_RuntimeAPIBind): 127.0.0.1 with Docker Desktop,
// which forwards the name to the host's loopback, and otherwise the default
// bridge network's gateway, which the host-gateway mapping names.
func dockerHostAddress(t *testing.T) string {
	t.Helper()
	osName, err := docker(t.Context(), "info", "--format", "{{.OperatingSystem}}")
	requireNoErr(t, err, "ask Docker what it runs on")
	if strings.Contains(osName, "Docker Desktop") {
		return "127.0.0.1"
	}
	gateways, err := docker(t.Context(), "network", "inspect", "bridge",
		"--format", "{{range .IPAM.Config}}{{.Gateway}} {{end}}")
	requireNoErr(t, err, "ask Docker for the bridge network's gateway")
	for _, g := range strings.Fields(gateways) {
		if ip := net.ParseIP(g); ip != nil && ip.To4() != nil {
			return g
		}
	}
	t.Fatalf("the bridge network has no IPv4 gateway: %q", gateways)
	return ""
}

// docker runs the docker CLI against the local daemon and returns its
// standard output.
func docker(ctx context.Context, args ...string) (string, error) {
	//nolint:gosec // G204: the docker CLI, with this suite's own arguments
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String(), nil
}

// fakeClock is the clock secret-store schedules rotations on in these
// tests: it starts at the system's time and moves only when the test
// advances it.
type fakeClock struct {
	now     time.Time
	waiters []clockWaiter
	mu      sync.Mutex
}

type clockWaiter struct {
	at time.Time
	ch chan time.Time
}

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
	c.waiters = append(c.waiters, clockWaiter{at: c.now.Add(d), ch: ch})
	return ch
}

// Advance moves the clock on by d and ends every wait that is over.
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

// waiting is how many waits are pending: the scheduler's, and one for each
// rotation waiting to retry.
func (c *fakeClock) waiting() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}

// rotationStack is identity, functions and secret-store wired together,
// with the secret app/db, a role for rotation functions, and clients signed
// with the root key.
type rotationStack struct {
	srv       *server
	functions *sibling
	clock     *fakeClock
	sm        *awssm.Client
	ic        *iam.Client
	lc        *lambda.Client
	secretARN string
}

// rotatorRole is the execution role the rotation functions run with.
const rotatorRole = "arn:aws:iam::000000000000:role/rotator"

// lambdaTrust lets Lambda assume a role, as an execution role's trust
// policy does.
const lambdaTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`

// rotatorPolicy is the policy the User Guide gives a rotation function's
// execution role ("Lambda rotation function execution role permissions"),
// for the secrets under app/, less what it allows on EC2.
var rotatorPolicy = policyDoc(
	statement{Effect: "Allow", Action: []string{
		"secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue",
		"secretsmanager:PutSecretValue", "secretsmanager:UpdateSecretVersionStage",
	}, Resource: []string{"arn:aws:secretsmanager:us-east-1:000000000000:secret:app/*"}},
	statement{
		Effect: "Allow", Action: []string{"secretsmanager:GetRandomPassword"},
		Resource: []string{"*"},
	},
)

func startFunctions(t *testing.T, identity *sibling) *sibling {
	t.Helper()
	return startSibling(t, "functions", functionsDirEnv, "TULE_Store_Path", map[string]string{
		"TULE_Auth_IdentityEndpoint":    identity.URL,
		"TULE_Functions_RuntimeAPIPort": "0",
	})
}

// newRotationStack starts the stack, with the rotator role given policy.
func newRotationStack(t *testing.T, policy string) *rotationStack {
	t.Helper()
	requireRotatorImage(t)
	identity := startIdentity(t, nil)
	functions := startFunctions(t, identity)
	clock := newFakeClock()
	srv := startServerWith(t, map[string]string{
		"TULE_Auth_IdentityEndpoint":   identity.URL,
		"TULE_Store_FunctionsEndpoint": functions.URL,
	}, serverOptions{clock: clock, listenHost: dockerHostAddress(t)})

	s := &rotationStack{
		srv: srv, functions: functions, clock: clock,
		sm: smFor(srv, rootCreds()), ic: iamFor(identity),
		lc: lambda.New(lambda.Options{
			Region:           signingRegion,
			BaseEndpoint:     aws.String(functions.URL),
			Credentials:      credentials.StaticCredentialsProvider{Value: rootCreds()},
			HTTPClient:       &http.Client{Timeout: clientTimeout},
			RetryMaxAttempts: 1,
		}),
	}
	s.secretARN = createSecret(t, s.sm, "app/db", "first-password")

	_, err := s.ic.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName: aws.String("rotator"), AssumeRolePolicyDocument: aws.String(lambdaTrust),
	})
	requireNoErr(t, err, "create the rotator role")
	_, err = s.ic.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
		RoleName: aws.String("rotator"), PolicyName: aws.String("rotation"),
		PolicyDocument: aws.String(policy),
	})
	requireNoErr(t, err, "put the rotator role's policy")
	return s
}

// rotator is the rotation function's name, and rotatorARN its ARN.
const (
	rotator    = "rotate"
	rotatorARN = "arn:aws:lambda:us-east-1:000000000000:function:" + rotator
)

// createRotator creates the function rotator from the rotator image,
// calling secret-store through the Docker host, with env added to its
// environment, and waits until it is Active.
func (s *rotationStack) createRotator(t *testing.T, env map[string]string) {
	t.Helper()
	_, port, err := net.SplitHostPort(s.srv.Addr)
	requireNoErr(t, err, "secret-store's port")
	vars := map[string]string{
		"AWS_ENDPOINT_URL_SECRETS_MANAGER": "http://host.docker.internal:" + port,
	}
	for k, v := range env {
		vars[k] = v
	}
	arch := lambdatypes.ArchitectureX8664
	if runtime.GOARCH == "arm64" {
		arch = lambdatypes.ArchitectureArm64
	}
	_, err = s.lc.CreateFunction(t.Context(), &lambda.CreateFunctionInput{
		FunctionName:  aws.String(rotator),
		Role:          aws.String(rotatorRole),
		PackageType:   lambdatypes.PackageTypeImage,
		Code:          &lambdatypes.FunctionCode{ImageUri: aws.String(rotatorImage)},
		Architectures: []lambdatypes.Architecture{arch},
		Timeout:       aws.Int32(30),
		Environment:   &lambdatypes.Environment{Variables: vars},
	})
	requireNoErr(t, err, "create the rotation function")
	w := lambda.NewFunctionActiveV2Waiter(s.lc, func(o *lambda.FunctionActiveV2WaiterOptions) {
		o.MinDelay, o.MaxDelay = 100*time.Millisecond, time.Second
	})
	requireNoErr(t, w.Wait(t.Context(), &lambda.GetFunctionInput{FunctionName: aws.String(rotator)},
		clientTimeout), "wait for the rotation function to be Active")
}

// allowSecretsManager adds the permission the User Guide adds ("Set up
// automatic rotation using the AWS CLI"): lambda:InvokeFunction for
// secretsmanager.amazonaws.com from the account, and, when sourceARN is
// set, from that secret only.
func (s *rotationStack) allowSecretsManager(t *testing.T, sourceARN string) {
	t.Helper()
	in := &lambda.AddPermissionInput{
		FunctionName:  aws.String(rotator),
		Action:        aws.String("lambda:InvokeFunction"),
		StatementId:   aws.String("SecretsManager"),
		Principal:     aws.String("secretsmanager.amazonaws.com"),
		SourceAccount: aws.String("000000000000"),
	}
	if sourceARN != "" {
		in.SourceArn = aws.String(sourceARN)
	}
	_, err := s.lc.AddPermission(t.Context(), in)
	requireNoErr(t, err, "add the Secrets Manager permission")
}

// rotate starts a rotation of app/db with the rotation function,
// immediately, with ClientRequestToken token, when set, and a schedule of
// days, when positive, and returns the version ID it answers.
func (s *rotationStack) rotate(t *testing.T, token string, days int64) string {
	t.Helper()
	in := &awssm.RotateSecretInput{
		SecretId: aws.String("app/db"), RotationLambdaARN: aws.String(rotatorARN),
	}
	if token != "" {
		in.ClientRequestToken = aws.String(token)
	}
	if days > 0 {
		in.RotationRules = &smtypes.RotationRulesType{AutomaticallyAfterDays: aws.Int64(days)}
	}
	out, err := s.sm.RotateSecret(t.Context(), in)
	requireNoErr(t, err, "rotate app/db")
	return aws.ToString(out.VersionId)
}

// describe returns app/db's description.
func (s *rotationStack) describe(t *testing.T) *awssm.DescribeSecretOutput {
	t.Helper()
	out, err := s.sm.DescribeSecret(t.Context(), &awssm.DescribeSecretInput{
		SecretId: aws.String("app/db"),
	})
	requireNoErr(t, err, "describe app/db")
	return out
}

// waitRotated waits until app/db's LastRotatedDate is at or after since.
func (s *rotationStack) waitRotated(t *testing.T, since time.Time) *awssm.DescribeSecretOutput {
	t.Helper()
	deadline := time.Now().Add(rotationWait)
	for time.Now().Before(deadline) {
		d := s.describe(t)
		if d.LastRotatedDate != nil && !d.LastRotatedDate.Before(since.Truncate(time.Millisecond)) {
			return d
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("app/db was not rotated within %s\nfunctions:\n%s", rotationWait,
		s.functions.out.String())
	return nil
}

// waitRetrying waits until a rotation is waiting to retry: a failed attempt
// has been recorded, and the run waits on the clock beside the scheduler.
func (s *rotationStack) waitRetrying(t *testing.T) {
	t.Helper()
	s.waitWaits(t, 2)
}

// waitWaits waits until n waits are pending on the clock.
func (s *rotationStack) waitWaits(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(rotationWait)
	for s.clock.waiting() != n {
		if time.Now().After(deadline) {
			t.Fatalf("%d waits pending on the clock after %s, want %d", s.clock.waiting(),
				rotationWait, n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// rotationWait bounds a rotation: four invocations, the first a cold
// start of the function's container.
const rotationWait = 90 * time.Second

// stagesOf returns the versions of app/db holding each label.
func (s *rotationStack) stagesOf(t *testing.T) map[string]string {
	t.Helper()
	byStage := map[string]string{}
	for id, stages := range s.describe(t).VersionIdsToStages {
		for _, st := range stages {
			byStage[st] = id
		}
	}
	return byStage
}

// step is one invocation of a rotation function, from functions' retrieval
// API: the step its event named, how it ended and the error it reported.
type step struct {
	Step         string
	Status       string
	Source       string
	ErrorMessage string
}

// steps returns the invocations of the rotation function, oldest first,
// read back from the functions service's retrieval API with the root key.
func (s *rotationStack) steps(t *testing.T) []step {
	t.Helper()
	var page struct {
		Items []struct {
			RequestID    string `json:"requestId"`
			Status       string `json:"status"`
			Source       string `json:"source"`
			ErrorMessage string `json:"errorMessage"`
		} `json:"items"`
	}
	s.retrieval(t, "/_functions/invocations", url.Values{
		"function": {rotator}, "limit": {"100"},
	}, &page)
	out := make([]step, 0, len(page.Items))
	for _, it := range page.Items {
		var detail struct {
			Payload string `json:"payload"`
		}
		s.retrieval(t, "/_functions/invocations/"+url.PathEscape(it.RequestID), nil, &detail)
		var ev struct{ Step, SecretID, ClientRequestToken string }
		requireNoErr(t, json.Unmarshal([]byte(detail.Payload), &ev), "decode the event")
		requireEqual(t, ev.SecretID, s.secretARN, "the event's SecretId")
		out = append(out, step{
			Step: ev.Step, Status: it.Status, Source: it.Source, ErrorMessage: it.ErrorMessage,
		})
	}
	slices.Reverse(out)
	return out
}

// retrieval GETs path of functions' retrieval API, signed with the root key
// for the lambda service, and decodes its answer into v.
func (s *rotationStack) retrieval(t *testing.T, path string, q url.Values, v any) {
	t.Helper()
	u := s.functions.URL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u, http.NoBody)
	requireNoErr(t, err, "build "+path)
	sum := sha256.Sum256(nil)
	requireNoErr(t, v4.NewSigner().SignHTTP(t.Context(), rootCreds(), req,
		hex.EncodeToString(sum[:]), "lambda", signingRegion, time.Now()), "sign "+path)
	res, err := (&http.Client{Timeout: clientTimeout}).Do(req)
	requireNoErr(t, err, "GET "+path)
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	requireNoErr(t, err, "read "+path)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, res.StatusCode, body)
	}
	requireNoErr(t, json.Unmarshal(body, v), "decode "+path)
}

// waitSteps waits until the rotation function has been invoked n times.
func (s *rotationStack) waitSteps(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(rotationWait)
	for len(s.steps(t)) < n {
		if time.Now().After(deadline) {
			t.Fatalf("the rotation function was not invoked %d times within %s", n, rotationWait)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// stepNames is the steps' names, in order.
func stepNames(steps []step) []string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.Step)
	}
	return out
}

// requireMessage fails unless err is an API error with message msg.
func requireMessage(t *testing.T, err error, msg string) {
	t.Helper()
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want an API error with message %q, got %v", msg, err)
	}
	requireEqual(t, apiErr.ErrorMessage(), msg, "error message")
}

//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// The checkouts of the sibling services the cross-service tests build, for a
// layout where they are not secret-store's siblings.
const (
	identityDirEnv = "TULE_E2E_IDENTITY_DIR"
	accountsDirEnv = "TULE_E2E_ACCOUNTS_DIR"
)

// The root key every service in these tests is configured with: the one
// clientFor signs with, so the secret-store harness needs no change.
const (
	rootKeyID  = "test"
	rootSecret = "test"
)

// signingRegion is the region IAM, STS and Organizations clients sign for.
const signingRegion = "us-east-1"

// syncBuffer collects a process's output, safe to write from the process's
// copying goroutines and read from the test.
type syncBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p) //nolint:wrapcheck // bytes.Buffer.Write never fails
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// sibling is a running sibling service process.
type sibling struct {
	cmd     *exec.Cmd
	exited  chan error
	out     *syncBuffer
	name    string
	URL     string
	stopped bool
}

// startSibling builds the service name from the checkout envVar names, or
// its default sibling path, runs it on a free port with a fresh store at
// storeKey and the root key, and returns it once it is ready. It is stopped
// when the test ends.
func startSibling(t *testing.T, name, envVar, storeKey string, env map[string]string) *sibling {
	t.Helper()

	bin := buildSibling(t, name, envVar)
	port := freePort(t)
	dir := t.TempDir()

	cmd := exec.Command(bin) //nolint:gosec // G204: the binary this test just built
	cmd.Dir = dir
	// The sibling gets only its own TULE_ variables, not those startServer
	// sets in this process for secret-store.
	cmd.Env = append(envWithoutTule(),
		"TULE_GasEnv=testing",
		"TULE_Server_Port="+strconv.Itoa(port),
		storeKey+"="+filepath.Join(dir, name+".db"),
		"TULE_Auth_AccessKeyID="+rootKeyID,
		"TULE_Auth_SecretAccessKey="+rootSecret,
	)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	s := &sibling{
		cmd:    cmd,
		exited: make(chan error, 1),
		out:    &syncBuffer{},
		name:   name,
		URL:    "http://127.0.0.1:" + strconv.Itoa(port),
	}
	cmd.Stdout = s.out
	cmd.Stderr = s.out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	go func() { s.exited <- cmd.Wait() }()
	t.Cleanup(func() { s.Stop(t) })

	s.waitReady(t)
	return s
}

// buildSibling builds the service name into a temporary directory.
func buildSibling(t *testing.T, name, envVar string) string {
	t.Helper()

	// The test runs in secret-store/test/e2e; by default the service is
	// secret-store's sibling. CI sets the directory. A missing checkout fails
	// the test, so the cross-service tests are never silently left out.
	src, from := os.Getenv(envVar), envVar
	if src == "" {
		src, from = filepath.Join("..", "..", "..", name), "the default sibling path"
	}
	src, err := filepath.Abs(src)
	requireNoErr(t, err, name+" directory")
	//nolint:gosec // G703: the checkout the test is told to build
	if _, err = os.Stat(filepath.Join(src, "go.mod")); err != nil {
		t.Fatalf("no %s checkout at %s (from %s); set %s to the %s checkout: %v",
			name, src, from, envVar, name, err)
	}

	bin := filepath.Join(t.TempDir(), "tule-"+name)
	//nolint:gosec // G204: go build of the checkout into this test's directory
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, out)
	}
	return bin
}

// envWithoutTule is this process's environment minus its TULE_ variables.
func envWithoutTule() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "TULE_") {
			env = append(env, kv)
		}
	}
	return env
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	requireNoErr(t, err, "find a free port")
	port := l.Addr().(*net.TCPAddr).Port
	requireNoErr(t, l.Close(), "release the free port")
	return port
}

// waitReady polls the service's readiness probe until it answers 200.
func (s *sibling) waitReady(t *testing.T) {
	t.Helper()

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(clientTimeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-s.exited:
			t.Fatalf("%s exited before it was ready: %v\n%s", s.name, err, s.out.String())
		default:
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, s.URL+"/_ready", nil)
		requireNoErr(t, err, "build readiness request")
		if res, err := client.Do(req); err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s was not ready within %v\n%s", s.name, clientTimeout, s.out.String())
}

// Stop interrupts the process, as a signal stops the service, and kills it
// if it does not exit in time. It is idempotent, so a test can stop the
// service early and let the cleanup run anyway.
func (s *sibling) Stop(t *testing.T) {
	t.Helper()

	if s.stopped {
		return
	}
	s.stopped = true

	_ = s.cmd.Process.Signal(os.Interrupt)
	select {
	case err := <-s.exited:
		if err != nil {
			t.Logf("%s exited: %v", s.name, err)
		}
	case <-time.After(clientTimeout):
		_ = s.cmd.Process.Kill()
		err := <-s.exited
		t.Errorf("%s did not stop on interrupt (%v)\n%s", s.name, err, s.out.String())
	}
}

// startIdentity runs identity with env setting extra TULE_ variables.
func startIdentity(t *testing.T, env map[string]string) *sibling {
	t.Helper()
	return startSibling(t, "identity", identityDirEnv, "TULE_Store_Path", env)
}

// startWithIdentity runs secret-store pointed at identity.
func startWithIdentity(t *testing.T, identity *sibling) *server {
	t.Helper()
	return startServer(t, map[string]string{"TULE_Auth_IdentityEndpoint": identity.URL})
}

func rootCreds() aws.Credentials {
	return aws.Credentials{AccessKeyID: rootKeyID, SecretAccessKey: rootSecret}
}

// smFor returns a Secrets Manager client for srv signing with creds. Retries
// are off, so a refused request fails at once with the error the service
// sent.
func smFor(srv *server, creds aws.Credentials) *awssm.Client {
	return clientFor(srv, func(o *awssm.Options) {
		o.Credentials = credentials.StaticCredentialsProvider{Value: creds}
		o.RetryMaxAttempts = 1
	})
}

func iamFor(identity *sibling) *iam.Client {
	return iam.New(iam.Options{
		Region:           signingRegion,
		BaseEndpoint:     aws.String(identity.URL),
		Credentials:      credentials.StaticCredentialsProvider{Value: rootCreds()},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
}

func stsFor(identity *sibling) *sts.Client {
	return sts.New(sts.Options{
		Region:           signingRegion,
		BaseEndpoint:     aws.String(identity.URL),
		Credentials:      credentials.StaticCredentialsProvider{Value: rootCreds()},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
}

func orgFor(accounts *sibling) *awsorg.Client {
	return awsorg.New(awsorg.Options{
		Region:           signingRegion,
		BaseEndpoint:     aws.String(accounts.URL),
		Credentials:      credentials.StaticCredentialsProvider{Value: rootCreds()},
		HTTPClient:       &http.Client{Timeout: clientTimeout},
		RetryMaxAttempts: 1,
	})
}

// createUserKey creates an IAM user named name in identity and returns its
// new access key.
func createUserKey(t *testing.T, ic *iam.Client, name string) aws.Credentials {
	t.Helper()

	_, err := ic.CreateUser(t.Context(), &iam.CreateUserInput{UserName: aws.String(name)})
	requireNoErr(t, err, "create user "+name)
	out, err := ic.CreateAccessKey(t.Context(), &iam.CreateAccessKeyInput{
		UserName: aws.String(name),
	})
	requireNoErr(t, err, "create access key for "+name)
	return aws.Credentials{
		AccessKeyID:     aws.ToString(out.AccessKey.AccessKeyId),
		SecretAccessKey: aws.ToString(out.AccessKey.SecretAccessKey),
	}
}

// readSecret reads the AWSCURRENT value of name and returns the error, for a
// read the test expects to be refused.
func readSecret(c *awssm.Client, name string) error {
	_, err := c.GetSecretValue(context.Background(), &awssm.GetSecretValueInput{
		SecretId: aws.String(name),
	})
	return err //nolint:wrapcheck // the SDK's error is what the test checks
}

// requireUnrecognized fails unless err is a 403 UnrecognizedClientException
// with AWS's message for a key or token it does not recognize.
func requireUnrecognized(t *testing.T, err error) {
	t.Helper()

	requireCode(t, err, "UnrecognizedClientException")
	requireResponse(t, err, http.StatusForbidden)
	var apiErr smithy.APIError
	errors.As(err, &apiErr) // requireCode has checked it is one
	requireEqual(t, apiErr.ErrorMessage(), msgInvalidToken, "error message")
}

// msgInvalidToken is AWS's message for an access key or session token it
// does not recognize.
const msgInvalidToken = "The security token included in the request is invalid."

func TestAnIdentityUserKeyIsAcceptedUntilItIsDeactivatedOrDeleted(t *testing.T) {
	identity := startIdentity(t, nil)
	srv := startWithIdentity(t, identity)
	ic := iamFor(identity)
	root := smFor(srv, rootCreds())

	userCreds := createUserKey(t, ic, "dev")
	// The key is evaluated against the user's policies, so it gets one for
	// what it does here.
	putDevPolicy(t, ic, allowDoc(
		[]string{"secretsmanager:CreateSecret", "secretsmanager:GetSecretValue"},
		"arn:aws:secretsmanager:*:*:secret:example/*"))
	user := smFor(srv, userCreds)

	// Every accepted principal shares the service's secrets, and the ARNs
	// keep the configured account.
	arn := createSecret(t, user, "example/from-user", "placeholder")
	if !strings.Contains(arn, ":000000000000:") {
		t.Fatalf("ARN %s does not carry the configured account", arn)
	}
	requireEqual(t, getSecretString(t, user, "example/from-user"), "placeholder", "user read")
	requireEqual(t, getSecretString(t, root, "example/from-user"), "placeholder", "root read")

	_, err := ic.UpdateAccessKey(t.Context(), &iam.UpdateAccessKeyInput{
		UserName:    aws.String("dev"),
		AccessKeyId: aws.String(userCreds.AccessKeyID),
		Status:      iamtypes.StatusTypeInactive,
	})
	requireNoErr(t, err, "deactivate the user's key")
	err = readSecret(user, "example/from-user")
	requireUnrecognized(t, err)
	requireEqual(t, getSecretString(t, root, "example/from-user"), "placeholder",
		"root read after deactivation")

	_, err = ic.DeleteAccessKey(t.Context(), &iam.DeleteAccessKeyInput{
		UserName:    aws.String("dev"),
		AccessKeyId: aws.String(userCreds.AccessKeyID),
	})
	requireNoErr(t, err, "delete the user's key")
	err = readSecret(user, "example/from-user")
	requireUnrecognized(t, err)
	requireEqual(t, getSecretString(t, root, "example/from-user"), "placeholder",
		"root read after deletion")
}

func TestAMemberAccountSessionIsVerifiedButDenied(t *testing.T) {
	accounts := startSibling(t, "accounts", accountsDirEnv, "TULE_Store_Path", nil)
	oc := orgFor(accounts)
	_, err := oc.CreateOrganization(t.Context(), &awsorg.CreateOrganizationInput{})
	requireNoErr(t, err, "create organization")
	created, err := oc.CreateAccount(t.Context(), &awsorg.CreateAccountInput{
		AccountName: aws.String("Member"),
		Email:       aws.String("member@example.com"),
	})
	requireNoErr(t, err, "create account")
	st := created.CreateAccountStatus
	if st == nil || st.State != orgtypes.CreateAccountStateSucceeded {
		t.Fatalf("create account: %+v", st)
	}
	member := aws.ToString(st.AccountId)

	identity := startIdentity(t, map[string]string{
		"TULE_Identity_AccountsEndpoint": accounts.URL,
	})
	srv := startWithIdentity(t, identity)

	assumed, err := stsFor(identity).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn: aws.String(
			"arn:aws:iam::" + member + ":role/OrganizationAccountAccessRole",
		),
		RoleSessionName: aws.String("e2e-session"),
	})
	requireNoErr(t, err, "assume role")
	session := aws.Credentials{
		AccessKeyID:     aws.ToString(assumed.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(assumed.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(assumed.Credentials.SessionToken),
	}

	sc := smFor(srv, session)
	sessionARN := "arn:aws:sts::" + member +
		":assumed-role/OrganizationAccountAccessRole/e2e-session"
	rootARN := createSecret(t, smFor(srv, rootCreds()), "example/from-root", "placeholder")

	// The session's signature verifies, and the role's AdministratorAccess
	// allows everything, but it is another account's: on AWS that needs a
	// resource-based policy too, which nothing here can grant.
	_, err = sc.CreateSecret(t.Context(), &awssm.CreateSecretInput{
		Name: aws.String("example/from-session"), SecretString: aws.String("placeholder"),
	})
	requireDenied(t, err, resourceDeny(sessionARN, "secretsmanager:CreateSecret",
		"example/from-session"))
	// Another account names a secret by ARN; by name it would be one of its
	// own account, which the store does not hold.
	err = readSecret(sc, rootARN)
	requireDenied(t, err, resourceDeny(sessionARN, "secretsmanager:GetSecretValue", rootARN))
	err = readSecret(sc, "example/from-root")
	requireCode(t, err, "ResourceNotFoundException")

	tampered := session
	tampered.SessionToken = tamper(session.SessionToken)
	err = readSecret(smFor(srv, tampered), rootARN)
	requireUnrecognized(t, err)

	// A session's key without its token is unknown, as on AWS.
	if !strings.HasPrefix(session.AccessKeyID, "ASIA") {
		t.Fatalf("session key %s is not a temporary key", session.AccessKeyID)
	}
	untokened := session
	untokened.SessionToken = ""
	err = readSecret(smFor(srv, untokened), rootARN)
	requireUnrecognized(t, err)
}

func TestIdentityGoingDownFailsClosed(t *testing.T) {
	identity := startIdentity(t, nil)
	srv := startWithIdentity(t, identity)
	root := smFor(srv, rootCreds())
	ic := iamFor(identity)
	user := smFor(srv, createUserKey(t, ic, "dev"))
	putDevPolicy(t, ic, allowDoc(
		[]string{"secretsmanager:GetSecretValue"}, "arn:aws:secretsmanager:*:*:secret:example/*"))

	createSecret(t, root, "example/app", "placeholder")
	requireEqual(t, getSecretString(t, user, "example/app"), "placeholder", "user read")

	identity.Stop(t)

	// identity being unreachable is the server's failure: never success, and
	// never the 403 of an unknown key.
	err := readSecret(user, "example/app")
	requireCode(t, err, "InternalServiceError")
	requireResponse(t, err, http.StatusInternalServerError)

	requireEqual(t, getSecretString(t, root, "example/app"), "placeholder",
		"root read with identity down")
}

// tamper changes one character in the middle of a token.
func tamper(token string) string {
	b := []byte(token)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

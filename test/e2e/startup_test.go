//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func TestProbesNeedNoCredentials(t *testing.T) {
	// The probes are what the image's HEALTHCHECK polls, so they are worth
	// exercising over the network and not only through a handler.
	srv := startServer(t, nil)

	for _, path := range []string{"/_health", "/_ready"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			srv.URL+path, nil)
		requireNoErr(t, err, "build request")

		res, err := srv.Client().Do(req)
		requireNoErr(t, err, "probe "+path)
		_ = res.Body.Close()
		requireEqual(t, res.StatusCode, http.StatusOK, "unsigned "+path)
	}
}

func TestUnsignedRequestIsRejected(t *testing.T) {
	srv := startServer(t, nil)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/", strings.NewReader(`{"SecretId":"example/app"}`))
	requireNoErr(t, err, "build request")
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")

	res, err := srv.Client().Do(req)
	requireNoErr(t, err, "unsigned request")
	defer func() { _ = res.Body.Close() }()

	requireEqual(t, res.StatusCode, http.StatusForbidden, "unsigned request status")
	requireEqual(t, errorType(t, res.Body), "MissingAuthenticationTokenException",
		"unsigned request error type")
}

func TestWrongCredentialsAreRejected(t *testing.T) {
	srv := startServer(t, nil)
	c := clientFor(srv, func(o *awssm.Options) {
		o.Credentials = credentials.NewStaticCredentialsProvider("other", "other", "")
	})

	_, err := c.GetSecretValue(context.Background(), &awssm.GetSecretValueInput{
		SecretId: aws.String("example/app"),
	})
	requireCode(t, err, "UnrecognizedClientException")
}

func TestUnknownOperationIsReported(t *testing.T) {
	srv := startServer(t, nil)
	c := clientFor(srv)

	// Reach past the SDK to send a target no Secrets Manager client would.
	_, err := c.GetSecretValue(context.Background(), &awssm.GetSecretValueInput{
		SecretId: aws.String("example/app"),
	}, func(o *awssm.Options) {
		o.APIOptions = append(o.APIOptions, setTargetHeader("secretsmanager.Nonsense"))
	})
	requireCode(t, err, "UnknownOperationException")
}

func TestSeededSecretsAndRestart(t *testing.T) {
	root := t.TempDir()
	seed := `{"example/seeded":{"Host":"db.internal"},"example/plain":"placeholder"}`
	env := map[string]string{
		"TULE_Store_RootDir": root,
		"TULE_Store_Seed":    seed,
	}

	c := clientFor(startServer(t, env))
	requireEqual(t, getSecretString(t, c, "example/seeded"), `{"Host":"db.internal"}`,
		"seeded object value")
	requireEqual(t, getSecretString(t, c, "example/plain"), "placeholder",
		"seeded string value")

	// Changes made at run time survive a restart, and seeding does not undo
	// them.
	_, err := c.PutSecretValue(context.Background(), &awssm.PutSecretValueInput{
		SecretId:     aws.String("example/plain"),
		SecretString: aws.String("changed"),
	})
	requireNoErr(t, err, "put secret value")

	c = clientFor(startServer(t, env))
	requireEqual(t, getSecretString(t, c, "example/plain"), "changed",
		"value after restart")
}

func TestStoreSurvivesRestartWithoutSeeding(t *testing.T) {
	root := t.TempDir()
	env := map[string]string{"TULE_Store_RootDir": root}

	c := clientFor(startServer(t, env))
	createSecret(t, c, "example/persisted", "v1")

	c = clientFor(startServer(t, env))
	requireEqual(t, getSecretString(t, c, "example/persisted"), "v1",
		"value after restart")

	listed, err := c.ListSecrets(context.Background(), &awssm.ListSecretsInput{})
	requireNoErr(t, err, "list secrets after restart")
	requireEqual(t, len(listed.SecretList), 1, "secrets after restart")
}

func TestInvalidSeedFailsStartup(t *testing.T) {
	// A malformed seed is a configuration mistake, so the app must not come up
	// pretending the secrets are there.
	t.Setenv("TULE_GasEnv", "testing")
	t.Setenv("TULE_Store_RootDir", t.TempDir())
	t.Setenv("TULE_Auth_AccessKeyID", "test")
	t.Setenv("TULE_Auth_SecretAccessKey", "test")
	t.Setenv("TULE_Store_Seed", "not json")

	err := startFailing(t)
	if err == nil {
		t.Fatal("want the app to refuse to start, got nil")
	}
	if !strings.Contains(err.Error(), "TULE_Store_Seed") {
		t.Fatalf("error = %v, want it to name the bad setting", err)
	}
}

func errorType(t *testing.T, body io.Reader) string {
	t.Helper()

	var envelope struct {
		Type string `json:"__type"`
	}
	if err := json.NewDecoder(body).Decode(&envelope); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	return envelope.Type
}

func TestSeedingSurvivesASoftDeletedSecret(t *testing.T) {
	root := t.TempDir()
	env := map[string]string{
		"TULE_Store_RootDir": root,
		"TULE_Store_Seed":    `{"example/seeded":"placeholder"}`,
	}

	c := clientFor(startServer(t, env))
	_, err := c.DeleteSecret(context.Background(), &awssm.DeleteSecretInput{
		SecretId: aws.String("example/seeded"),
	})
	requireNoErr(t, err, "delete the seeded secret")

	// Nothing sweeps a scheduled deletion here, so a seed that treated it as
	// absent would fail every restart from now on, with no way out but
	// deleting the data directory.
	c = clientFor(startServer(t, env))

	described, err := c.DescribeSecret(context.Background(), &awssm.DescribeSecretInput{
		SecretId: aws.String("example/seeded"),
	})
	requireNoErr(t, err, "describe the seeded secret after restart")
	if described.DeletedDate == nil {
		t.Fatal("seeding resurrected a secret that was scheduled for deletion")
	}
}

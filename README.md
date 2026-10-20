# secret-store

An AWS Secrets Manager-compatible secret store that keeps secrets on the local
filesystem. It is built to stand in for Secrets Manager in local development
and end-to-end tests: point an AWS SDK at it and the usual secret, version and
staging-label calls work.

It is not a production secret store. Values are kept as plain JSON files on one
machine, nothing is encrypted, and the one access key it accepts has access to
every secret.

## Running it

With Docker:

```sh
docker run --rm -p 9010:9010 -v secretdata:/data \
  -e TULE_Auth_AccessKeyID=test -e TULE_Auth_SecretAccessKey=test \
  -e TULE_Store_Seed='{"myapp/config":{"Database":{"Host":"db.internal"}}}' \
  ghcr.io/tulehq/secret-store:latest
```

The image is based on Alpine, so `docker exec -it <container> sh` gives you a
shell. It runs as the unprivileged `nonroot` user, and its Docker health check
polls `/_ready`.

From source (Go 1.27):

```sh
make build
TULE_Auth_AccessKeyID=test TULE_Auth_SecretAccessKey=test ./build/tule-secret-store
```

It listens on port 9010, so it does not collide with
[object-store](https://github.com/tulehq/object-store) on 9000.

## Configuration

Settings come from environment variables prefixed with `TULE_`, and from a
`.env` file in the working directory (without the prefix).

| Variable | Default | Purpose |
|---|---|---|
| `TULE_Server_Port` | `9010` | Listen port |
| `TULE_Store_RootDir` | `./data` (`/data` in the image) | Where secrets are stored |
| `TULE_Store_Region` | `us-east-1` | Region in the ARNs the store mints |
| `TULE_Store_AccountID` | `000000000000` | Account in the ARNs the store mints |
| `TULE_Store_Seed` | unset | JSON object of secret name to value, created at startup if missing |
| `TULE_HSTS_MaxAge` | unset | `Strict-Transport-Security` max age; the header is only sent when set |
| `TULE_Server_ReadTimeout` | `30s` | How long the server may take to read a request, body included |
| `TULE_Server_WriteTimeout` | `30s` | How long it may take to write a response |
| `TULE_Server_IdleTimeout` | `2m` | How long a keep-alive connection may sit idle between requests |
| `TULE_Server_ShutdownTimeout` | `5s` | How long a graceful shutdown waits for in-flight requests |
| `TULE_Auth_AccessKeyID` | required | The access key clients sign requests with |
| `TULE_Auth_SecretAccessKey` | required | Its secret |
| `TULE_GasEnv` | | `development` logs console output at trace level, `production` logs at warn level, `testing` disables logging |

The read and write timeouts are sized for a signed request body of up to 1 MiB,
which is the largest this service accepts. Logs go to the console only; there
is no log shipping.

The server refuses to start without an access key, because every request is
verified against it and any web page the developer has open can reach a server
on localhost.

`TULE_Store_Seed` is read as a JSON object: each key is a secret name, and each
value becomes that secret's value, a JSON string unquoted and anything else
stored as its JSON. Seeded secrets are created before the server listens and
existing secrets are left alone, so a restart keeps whatever the app wrote.
Seeding through the environment is for local fixtures; it is not a way to hand
real secrets to a deployment.

## Health checks

`GET /_health` (liveness) and `GET /_ready` (readiness) answer without a
signature. They respond `200` when every service reports healthy or ready and
`503` otherwise, with a JSON object of each service's status. Readiness fails
when the store directory cannot be read.

Seeded secrets are created before the server listens, so once either probe
answers, they exist.

## Connecting a client

Use any region; the ARNs the store mints report `TULE_Store_Region`. Every call
is a signed `POST /` whose `X-Amz-Target` header names the operation, which is
the AWS JSON 1.1 protocol the SDKs already speak.

Go (AWS SDK v2):

```go
client := secretsmanager.New(secretsmanager.Options{
	Region:       "us-east-1",
	BaseEndpoint: aws.String("http://localhost:9010"),
	Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
})
```

JavaScript (AWS SDK v3):

```js
const client = new SecretsManagerClient({
  region: "us-east-1",
  endpoint: "http://localhost:9010",
  credentials: { accessKeyId: "test", secretAccessKey: "test" },
});
```

A [gas](https://github.com/gasmod/gas) app resolves its config secrets from it
with the `secretsmanager` config provider:

```go
store := config.New(
	config.WithProvider(secretsmanager.NewProvider(
		secretsmanager.WithEndpoint("http://localhost:9010"),
		secretsmanager.WithRegion("us-east-1"),
		secretsmanager.WithStaticCredentials("test", "test"),
		secretsmanager.WithSecret("myapp/config"),
		secretsmanager.WithSecretAtKey("myapp/token", "Database.Token"),
	)),
)
```

Or with `curl`, which signs requests too:

```sh
curl -fsS --aws-sigv4 aws:amz:us-east-1:secretsmanager --user test:test \
  -H 'Content-Type: application/x-amz-json-1.1' \
  -H 'X-Amz-Target: secretsmanager.GetSecretValue' \
  --data-binary '{"SecretId":"myapp/config"}' http://localhost:9010/
```

## Supported operations

| Operation | Notes |
|---|---|
| `CreateSecret` | `ClientRequestToken` becomes the first version's ID |
| `GetSecretValue` | By `VersionId` or `VersionStage`, defaulting to `AWSCURRENT` |
| `PutSecretValue` | Moves `AWSCURRENT` and `AWSPREVIOUS`, or sets the stages you ask for |
| `UpdateSecret` | Changes the description, and stores a new current version when given a value |
| `DescribeSecret` | Also answers for a secret scheduled for deletion |
| `DeleteSecret` | Schedules deletion after 7 to 30 days, or `ForceDeleteWithoutRecovery` |
| `RestoreSecret` | Cancels a scheduled deletion |
| `ListSecrets` | Paginated, in name order |
| `ListSecretVersionIds` | Paginated, newest version first |
| `UpdateSecretVersionStage` | Moves one staging label; moving `AWSCURRENT` carries `AWSPREVIOUS` to the version it left, and a label held by another version needs `RemoveFromVersionId` |
| `TagResource` / `UntagResource` | Tags are stored and reported, not matchable |
| `BatchGetSecretValue` | By `SecretIdList`, reporting per-secret errors |

A secret is addressable by name, by its full ARN, or by its ARN without the
random suffix, as Secrets Manager allows. Both string and binary values round
trip, and a read reports back whichever kind was written. A value is capped at
65536 bytes, as on AWS, so a secret that is accepted here is accepted there.

`ClientRequestToken` works as an idempotency token on `CreateSecret`,
`PutSecretValue` and `UpdateSecret`: reusing one with the same value returns
the version already stored, and reusing one with a different value is a
`ResourceExistsException`.

## Differences from AWS

- **Nothing is encrypted.** Each secret is one JSON file under
  `TULE_Store_RootDir`, named after a hash of the secret's name, holding its
  metadata and every version of its value in the clear.
- **One access key.** It can read and write every secret. There are no IAM
  policies, no resource policies and no per-secret permissions, so nothing
  here tells you whether a deployment's policies are right.
- **`KmsKeyId` is stored but does nothing.** It is kept with the secret and
  reported back by `DescribeSecret` and `ListSecrets`, so a client sees its own
  setting, and the server logs a warning naming any secret that asks for a key.
  The value beside it is still in the clear. Other request fields the service
  does not model (`AddReplicaRegions`, `ForceOverwriteReplicaSecret`,
  `RotationToken`) are ignored outright, since the AWS JSON protocol ignores
  unknown fields.
- **No filtering or sorting.** `Filters`, `SortBy` and `SortOrder` are
  rejected with `InvalidParameterException` rather than ignored, so a filtered
  listing never looks like a filter that matched everything. List and filter
  client-side.
- **`BatchGetSecretValue` is not paginated.** It answers in one page and
  rejects a `NextToken`.
- **Scheduled deletions are never swept.** `DeleteSecret` records a deletion
  date and the secret stops answering everything but `DescribeSecret` and
  `RestoreSecret`, but nothing removes it when that date passes;
  `ForceDeleteWithoutRecovery` removes it immediately.
- **Versions are never pruned.** AWS deprecates versions beyond its per-secret
  limit; here every version a secret has ever held stays readable by its
  version ID, and `ListSecretVersionIds` reports the unlabelled ones with
  `IncludeDeprecated`.
- **`LastAccessedDate` has day granularity,** as on AWS, and is only written
  when the day changes.
- **No rotation, no replication, no resource policies.** These return
  `501 NotImplemented` with a `NotImplementedException`: `RotateSecret`,
  `CancelRotateSecret`, `GetRandomPassword`, `PutResourcePolicy`,
  `GetResourcePolicy`, `DeleteResourcePolicy`, `ValidateResourcePolicy`,
  `ReplicateSecretToRegions`, `RemoveRegionsFromReplication` and
  `StopReplicationToReplica`. A target that names no Secrets Manager
  operation gets `UnknownOperationException`.
- **Signature verification is request-level.** The method, path, query, signed
  headers and the body's hash are checked, along with the credential's access
  key and a 15-minute clock skew. There are no presigned URLs in this
  protocol. A request body larger than 1 MiB is refused. A signature must
  cover `host`, `x-amz-date` and `x-amz-target`, and must carry a real SHA-256
  of the body: `UNSIGNED-PAYLOAD` is rejected, since it would leave the body
  outside the signature and let a relay swap one operation's body for
  another's.
- **Writes are not fsynced.** Each change is written to a temporary file and
  renamed over the old one, so a reader never sees half a secret, but the data
  is only as durable as the page cache: a power loss can lose a write that was
  already acknowledged. Likewise the store assumes a single process: one lock
  inside this server serializes its own writes, and nothing coordinates two
  servers pointed at the same directory.
- **Logs record the connection's peer address.** `X-Forwarded-For` is not
  trusted, since nothing is expected in front of this service and the header
  is unsigned.
- **Stricter than AWS in one place.** Removing `AWSCURRENT` from a version
  without moving it elsewhere is refused with `InvalidParameterException`. The
  AWS documentation does not say what the real service does here, so this is a
  deliberate choice rather than a matched behaviour: a secret with no current
  version answers no ordinary read, and a client cannot put it right without a
  version ID it has no way to discover.

## Development

```sh
make test       # unit tests
make test-e2e   # end-to-end tests: the app in-process, driven by the AWS SDK
make lint
make image      # build ghcr.io/tulehq/secret-store:dev
make smoke      # build the image, run it, and check it serves signed requests
make push VERSION=0.1.0   # build for amd64 and arm64 and push
```

## License

[MIT](LICENSE)

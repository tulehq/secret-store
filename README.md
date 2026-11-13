# secret-store

An AWS Secrets Manager-compatible secret store that keeps secrets on the local
filesystem. It is built to stand in for Secrets Manager in local development
and end-to-end tests: point an AWS SDK at it and the usual secret, version and
staging-label calls work.

It is not a production secret store. Values are kept as plain JSON files on one
machine and nothing is encrypted. The root key has access to every secret;
the keys [identity](https://github.com/tulehq/identity) issues have what their
IAM policies and the secrets' resource policies allow.

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

From source (Go 1.27.4 or later):

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
| `TULE_Server_ReadHeaderTimeout` | `30s` | How long it may take to read a request's headers; must be positive |
| `TULE_Server_WriteTimeout` | `30s` | How long it may take to write a response |
| `TULE_Server_IdleTimeout` | `2m` | How long a keep-alive connection may sit idle between requests |
| `TULE_Server_ShutdownTimeout` | `7s` | How long a graceful shutdown waits for in-flight requests |
| `TULE_Auth_AccessKeyID` | required | The root key clients sign requests with; it must be identity's root key when `TULE_Auth_IdentityEndpoint` is set |
| `TULE_Auth_SecretAccessKey` | required | Its secret |
| `TULE_Auth_IdentityEndpoint` | unset | The [identity](https://github.com/tulehq/identity) service's base URL, such as `http://localhost:9030`, to also accept the keys it issues, each request evaluated against the principal's IAM policies. Unset, only the root key is accepted |
| `TULE_GasEnv` | | `development` logs console output at trace level, `production` logs at warn level, `testing` disables logging |

The read and write timeouts are sized for a signed request body of up to 1 MiB,
which is the largest this service accepts. Logs go to the console only; there
is no log shipping.

The server refuses to start without an access key, because every request is
verified against it and any web page the developer has open can reach a server
on localhost. It also refuses an identity endpoint that is not an `http` or
`https` URL.

### Keys issued by identity

With `TULE_Auth_IdentityEndpoint` set, a request signed with any other key is
verified against identity's signing-key endpoint: its IAM users' access keys
and the session keys of the roles it lets you assume, token and all. The
root key is checked locally first, without asking identity, and it is also
what the calls to identity are signed with, so it must be identity's root
key: `TULE_Auth_AccessKeyID` and `TULE_Auth_SecretAccessKey` set to the same
values on both services.

identity is asked on every request and nothing is cached, so a key it
deactivates or deletes is refused on the next request, with
`UnrecognizedClientException`. A session token that is not the key's is
refused the same way, and an expired one with `ExpiredTokenException`. A
lookup that fails, such as identity being unreachable or not answering within
10 seconds, fails the request with `500 InternalServiceError`; it is never
treated as an unknown key or as a valid one, and the root key keeps working.

Unset, the service runs on its own exactly as without identity: only the
root key is accepted, and identity is never contacted.

identity v0.4.0 or later is required: the service asks the signing-key
endpoint (version 3) for each principal's policies and attributes (a
session's role ARN with its path, the unique ID, the principal type and the
tags), and an older identity, which cannot report them, fails every request
signed with one of its keys with `InternalServiceError`.

### IAM policies

Every request signed with a key identity issued, an IAM user's or a role
session's, is evaluated against that principal's identity-based policies
(inline and attached managed, as identity reports them, a session carrying
its role's) and the resource-based policy of the secret it acts on,
together, with [tule.dev/policy](https://github.com/tulehq/policy)'s
`Authorize` and AWS's logic (see [Resource policies](#resource-policies)). The root key is never evaluated, as AWS never evaluates an
account's root user, and without `TULE_Auth_IdentityEndpoint` it is the only
key, so nothing is ever evaluated. Root means the root of
`TULE_Store_AccountID`: the static key is that account's root, and a root
principal identity reports for any other account is evaluated like any
principal of another account (see below). A principal whose root flag and
type disagree (an `Account` principal that is not root, or a root one of
another type) fails the request with `InternalServiceError`, never evaluated
under either reading.

**This is a breaking change.** Before, every key identity issued could read
and write every secret. Now a key whose principal has no policy is denied
every operation. Give the user or role a policy for what it does, for
example:

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
    "Resource": "arn:aws:secretsmanager:us-east-1:000000000000:secret:myapp/*"
  }
}
```

A denied request is answered `400 AccessDeniedException`, the code and status
Secrets Manager's common errors give, with AWS's message:

```
User: arn:aws:iam::000000000000:user/dev is not authorized to perform: secretsmanager:GetSecretValue on resource: myapp/config because no identity-based policy allows the secretsmanager:GetSecretValue action
```

or, by the reason tule.dev/policy gives, `... with an explicit deny in an
identity-based policy`, `... with an explicit deny in a resource-based
policy` or `... because no resource-based policy allows the <action> action`
(IAM User Guide, "Troubleshoot access denied error messages"). When both
kinds deny, the identity-based one is named. The resource in the message is the `SecretId` (or `Name`) as the
request gave it, as Secrets Manager's own messages show it, or `*`; the
policy is evaluated on the secret's full ARN.

### Changes from v0.3.0

- **identity v0.4.0 is required** (signing-key version 3); an older identity
  fails every request signed with its keys with `InternalServiceError`.
- **Cross-account requests are evaluated, no longer refused.** A principal
  of another account was denied every operation; it is now allowed what its
  identity policies and the secret's resource policy both grant. A
  cross-account request on a secret without a resource policy is still
  denied, with the same `because no resource-based policy allows ...`
  message, and another account's root user now gets that message too where
  it got `because no identity-based policy allows ...`.
- **`aws:PrincipalArn` carries a role's path.** A condition on a role ARN
  with its path now matches the role's sessions, so a `Deny` written that way
  now applies; one written on the path-less ARN of a role that has a path no
  longer matches. `aws:userid`, `aws:PrincipalType` and
  `aws:PrincipalTag/<key>` are now supplied.
- **The resource-policy operations are served**, where they answered `501`.
- A principal whose root flag and type disagree fails with
  `InternalServiceError`.

### Resource policies

A secret's resource policy is attached with `PutResourcePolicy`, read with
`GetResourcePolicy`, removed with `DeleteResourcePolicy` and checked with
`ValidateResourcePolicy` (see [Supported operations](#supported-operations)).
It is stored in the secret's own file and read under the same lock as the
secret, so the policy a check evaluates is always the one stored for the
secret acted on. It is evaluated with the principal's identity policies as
the IAM User Guide's "Policy evaluation logic" and "Cross-account policy
evaluation logic" describe:

- An explicit `Deny` in either kind of policy denies.
- **Same account** (a principal of `TULE_Store_AccountID`): an `Allow` in
  either kind allows. A resource policy that names the principal directly,
  by its user ARN, its role's ARN (path included; it reaches the role's
  sessions), its session ARN or `"*"`, is enough without any identity
  policy. One that names only the account (`000000000000` or
  `arn:aws:iam::000000000000:root`) delegates to the account and also needs
  the principal's identity `Allow`.
- **Another account**: both an identity `Allow` in the caller's account and
  a resource-policy `Allow` naming it, directly or through its account, are
  needed. Another account's root user needs only the resource-policy grant.
  `ListSecrets` and `CreateSecret` act on the store's own account, which no
  resource policy covers, so another account's principal is denied them
  (`because no resource-based policy allows ...`).
  Another account must name a secret by its ARN, as Secrets Manager
  requires ("To retrieve a secret from another account, you must use an
  ARN."; GetSecretValue, API reference): a name is read in the caller's own
  account, where the store holds no secret, so it is evaluated there as a
  missing secret, without any resource policy, and answered
  `ResourceNotFoundException` when the caller's identity policies allow it.
  The store's secret of that name, its policy and its existence play no
  part. This holds for every operation that takes a `SecretId`, and per
  entry in `BatchGetSecretValue`.
- **Cross-account `BatchGetSecretValue` is served** (this service's choice):
  AWS's cross-account documentation does not list it, but it reaches
  nothing `GetSecretValue` cannot. Its own action is evaluated as the
  caller's own, and then each secret, named by ARN, with its own policy.
- A session whose role was deleted is denied everything.
- A stored policy that no longer parses fails every evaluated request on its
  secret with `InternalServiceError` (fail closed); the root key still
  reaches the secret, and can replace or delete the policy.

A secret scheduled for deletion keeps its policy: its `DescribeSecret` and
`RestoreSecret` are evaluated with it, a restored secret has it again, and
only a purge (`ForceDeleteWithoutRecovery`) removes it, with the secret.

The mapping from operations to actions is
[internal/authz/mapping.go](internal/authz/mapping.go), taken from AWS's
Service Authorization Reference for Secrets Manager; a test checks every
routed operation has an entry, and every entry against a copy of the
reference.

| Operation | Actions | Resource |
|---|---|---|
| `CreateSecret` | `secretsmanager:CreateSecret`, and `secretsmanager:TagResource` when the request has `Tags` | the new secret's ARN, suffix included |
| `BatchGetSecretValue` | `secretsmanager:BatchGetSecretValue`, then `secretsmanager:GetSecretValue` for each secret | `*`, then each secret |
| `ListSecrets` | `secretsmanager:ListSecrets` | `*` |
| every other operation | `secretsmanager:<Operation>` | the secret |

The new secret's ARN is minted before `CreateSecret` is evaluated, so a
`secret:myapp/config-??????` resource grants creating that secret, as AWS
documents. A secret is always evaluated on an ARN rebuilt from this store's
partition, region and account and the secret the operation acts on, never on
the string the request gave. A secret that does not exist is evaluated on
`arn:aws:secretsmanager:<region>:<account>:secret:<name>` for a name, or on
the ARN given when it is this store's, so a caller that may not touch it is
denied rather than told it is missing. A `SecretId` that is an ARN of another
partition, region or account names no secret here and is answered
`ResourceNotFoundException` without being evaluated, as a regional endpoint
does for a secret it does not hold.

A `CreateSecret` or `TagResource` whose `Tags` repeat a key is refused with
`InvalidParameterException` (`Duplicate tag keys in request`) before it is
evaluated, so a secret's tag keys are unique and each `aws:RequestTag/<key>`
has one value. IAM matches condition key names regardless of case, so for a
principal that is evaluated, tag keys that differ only by case (`Env` and
`env`), in one request or between a request and the secret's stored tags,
are refused the same way; the root key may still write them, and a secret
that holds such keys fails every evaluated check with
`InternalServiceError` rather than be evaluated on a merged key. A secret's tags are always loaded for its checks, whatever
the policies mention.

A check on a secret runs inside the store, under the lock the operation acts
under, on the secret the store resolved for it: the record checked is the
record acted on, with the tags it has at that moment, so a concurrent write
can neither swap the secret nor leave a stale tag between the two. An ARN
ending in a hyphen and six characters is read as a full ARN only, naming the
secret whose ARN it is exactly or nothing, so a secret named `<name>-<suffix>`
cannot capture reads by another's ARN (see below).
In `BatchGetSecretValue`, a secret the caller may not read is reported in
`Errors` with `AccessDeniedException`, and the others are returned.

The condition keys supplied with every request are `aws:SourceIp` (the
connection's peer address), `aws:CurrentTime`, `aws:EpochTime`,
`aws:SecureTransport`, `aws:RequestedRegion` (`TULE_Store_Region`: the
service's region, never the region the request was signed for, which any
caller may choose since the signature's region is not checked),
`aws:PrincipalTag/<key>` for each of the principal's tags (a user's own, or
a session's role's; identity issues no session tags), and, from the
principal identity reports, `aws:PrincipalAccount`, `aws:PrincipalArn` (a
user's ARN, or for a role session its role's ARN with its path),
`aws:userid`, `aws:PrincipalType` and, for a user, `aws:username`. With an
action on a secret come `secretsmanager:SecretId` (its ARN),
`secretsmanager:SecretPrimaryRegion` (`TULE_Store_Region`) and its tags as
`aws:ResourceTag/<key>` and `secretsmanager:ResourceTag/<key>`. By operation:
`secretsmanager:Name`, `secretsmanager:Description` and
`secretsmanager:KmsKeyId` on `CreateSecret`; `secretsmanager:Description` and
`secretsmanager:KmsKeyId` on `UpdateSecret`; `secretsmanager:VersionId` and
`secretsmanager:VersionStage` on `GetSecretValue`;
`secretsmanager:VersionStage` on `UpdateSecretVersionStage`;
`secretsmanager:ForceDeleteWithoutRecovery` (when true) and
`secretsmanager:RecoveryWindowInDays` on `DeleteSecret`;
`aws:RequestTag/<key>` and `aws:TagKeys` on `CreateSecret` and `TagResource`,
`aws:TagKeys` on `UntagResource`; and `secretsmanager:PolicyName` on the
resource-policy operations and `secretsmanager:BlockPublicPolicy` on
`PutResourcePolicy`. A key is supplied only when the request
carries its value.

The condition context of one evaluation is capped (256 keys, 64 values per
key, 4096 bytes per value, 256 KiB in all), well above what AWS lets one
request carry, since evaluation cost grows with it. A request beyond the cap
is refused with `InvalidParameterException`, never evaluated on a truncated
context. The resource is bounded too: a `SecretId` longer than 2048
characters or a `Name` longer than 512, the API reference's limits, is
refused with `ValidationException` before anything is evaluated, from any
caller.

Parsed policy documents are cached by content hash, up to 1024 identity
policies and 1024 resource policies. The
policies themselves are fetched from identity on every request, so a policy
change applies on the next one. A policy identity reports that does not parse
fails the request with `InternalServiceError`.

What is not enforced:

- **Unique IDs in stored resource policies.** AWS converts a user or role
  ARN in a resource policy to the principal's unique ID when it is stored,
  so a principal recreated under the same name does not inherit the grant.
  Here principals are matched by ARN: a recreated user or role does inherit
  it, until identity can resolve unique IDs for the services.
- **`aws:PrincipalOrgID` and `aws:PrincipalOrgPaths`** are not supplied
  (identity does not carry the organization). A positive condition on them
  (`StringEquals` and the like) never holds, and a negated one
  (`StringNotEquals` and the like) always does, so a `Deny` written with a
  negated operator on them, such as "deny anyone outside my organization",
  denies every evaluated principal.
- **Service principals** in a resource policy never match: no caller here is
  an AWS service.
- **`secretsmanager:KmsKeyArn`, `secretsmanager:Type`,
  `secretsmanager:resource/Type`, `secretsmanager:resource/AllowRotationLambdaArn`**
  and the replication and rotation keys are not supplied; nothing here
  models KMS, rotation or replication.
- **Permissions boundaries, session policies, SCPs and RCPs** are not
  evaluated, so a resource-policy grant to a role ARN or through
  `aws:PrincipalArn`, which AWS lets them limit, is unlimited here.
- **TagResource and UntagResource do not check the caller keeps access.** AWS
  blocks a tag change that would cost the caller its permissions on the
  secret (TagResource, API reference); here it is applied.
- **The 501 operations** answer 501 to every caller without evaluating a
  policy.
- There is no retrieval or inspection API outside Secrets Manager's own, so
  there is no `tule:Inspect` action here.

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
| `TagResource` / `UntagResource` | Tags are stored and reported, and reach IAM conditions as `aws:ResourceTag/<key>`; list filters on them are refused |
| `BatchGetSecretValue` | By `SecretIdList`, reporting per-secret errors |
| `PutResourcePolicy` | Attaches the secret's one policy, `default`, replacing any; see below |
| `GetResourcePolicy` | Without a policy, answers the secret's `ARN` and `Name` only |
| `DeleteResourcePolicy` | Succeeds whether or not the secret has a policy |
| `ValidateResourcePolicy` | Checks syntax and broad access without storing; `SecretId` optional |

The resource-policy operations follow the API reference: a `ResourcePolicy`
of 1 to 20,480 characters (the "Resource-based policy length" quota counts
characters, not bytes), otherwise `ValidationException`; a `PolicyName`, when
given, of 1 to 64 characters matching `[0-9A-Za-z\-\_]+`, and only
`default`: another name is `InvalidParameterException` on
`PutResourcePolicy` and `DeleteResourcePolicy` and
`ResourceNotFoundException` on `GetResourcePolicy`; and on a secret scheduled
for deletion, `InvalidRequestException`, as the reference lists for all four.
A document that is not a valid resource-based policy as tule.dev/policy's
`ParseResource` reads one (each statement needs a `Principal` or
`NotPrincipal` and a `Resource`; groups, `Federated` principals and partial
wildcards in principals are refused) is `MalformedPolicyDocumentException`
with the parser's message, and is never stored. Secrets Manager documents no
`Sid` rule of its own, so any `Sid` string unique in the policy is accepted,
as `ParseResource` accepts it. Length, name and syntax are checked before the
request is evaluated, so a caller not allowed the action still learns that
its document is malformed; AWS does not document the order.

With `BlockPublicPolicy` set, a policy that grants broad access is refused
with `PublicPolicyException`. AWS decides this with Zelkova and documents no
exact rule ("for example those that use a wildcard for the principal"), so
this service applies the rule AWS documents for S3 bucket policies ("The
meaning of 'public'"): an `Allow` whose `Principal` is `"*"` is broad unless
its `Condition` fixes, with values holding no wildcard or policy variable,
one of `aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:PrincipalOrgID`,
`aws:userid` (`AROA...:*` counts as fixed), `aws:SourceArn`, `aws:SourceVpc`,
`aws:SourceVpce`, `aws:SourceOwner`, `aws:SourceAccount`, or `aws:SourceIp`
with ranges no broader than a `/8` (IPv4) or `/32` (IPv6). Locally that last
rule is weak: every caller of a store on a developer's machine connects from
loopback, so `"Principal": "*"` with `aws:SourceIp` `127.0.0.0/8` is not
refused as public, yet it reaches every principal of every account (one of
another account still needs its identity `Allow`). Only positive
operators (`StringEquals`, `StringEqualsIgnoreCase`, `StringLike`,
`ArnEquals`, `ArnLike`, `IpAddress`, plain or `ForAnyValue:`) fix a key;
`...IfExists` and `ForAllValues:` do not. `ValidateResourcePolicy` reports
the same finding as `PolicyValidationPassed: false` with one
`ValidationErrors` entry, `{"CheckName": "BROAD_ACCESS", "ErrorMessage":
...}`; AWS documents the entry's shape but not its check names, so the name
and both messages are this service's own. It does not make AWS's third
check, that the policy does not lock out the caller. It needs
`secretsmanager:ValidateResourcePolicy` and `secretsmanager:PutResourcePolicy`,
on the secret (with its stored policy) or, without a `SecretId`, on `*`.

A secret is addressable by name, by its full ARN, or by its ARN without the
random suffix, as Secrets Manager allows. An ARN whose last segment ends in a
hyphen and six characters is always read as a full ARN: with no secret of
exactly that ARN it is `ResourceNotFoundException`, never a partial ARN of a
secret whose name ends that way. Secrets Manager's troubleshooting guide
gives the same reading ("If your secret name ends with a hyphen and six
characters, using only part of the ARN can appear to Secrets Manager as
though you are specifying a full ARN"); use the name or the full ARN of
such a secret. Both string and binary values round
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
- **One account's secrets.** Every secret belongs to `TULE_Store_AccountID`,
  and a principal of another account reaches one only through its resource
  policy (see [Resource policies](#resource-policies)). Identity-based and
  resource-based policies are enforced.
- **`KmsKeyId` is stored but does nothing.** It is kept with the secret and
  reported back by `DescribeSecret` and `ListSecrets`, so a client sees its own
  setting, and the server logs a warning naming any secret that asks for a key.
  The value beside it is still in the clear. Other request fields the service
  does not model (`AddReplicaRegions`, `ForceOverwriteReplicaSecret`,
  `RotationToken`) are ignored outright, since the AWS JSON protocol ignores
  unknown fields.
- **Ambiguous JSON bodies are refused.** A body that names a member twice,
  regardless of case, or spells a member in another case (`secretId` for
  `SecretId`) is answered `SerializationException`. The body is decoded once,
  and that one reading is both what a request is authorized on and what it
  acts on; refusing these keeps that reading the exact one. AWS does not
  document its handling of either.
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
- **No rotation, no replication.** These return
  `501 NotImplemented` with a `NotImplementedException`: `RotateSecret`,
  `CancelRotateSecret`, `GetRandomPassword`, `ReplicateSecretToRegions`, `RemoveRegionsFromReplication` and
  `StopReplicationToReplica`. A target that names no Secrets Manager
  operation gets `UnknownOperationException`.
- **Signature verification is request-level.** The method, path, query, signed
  headers and the body's hash are checked, along with the credential's access
  key, its service, which must be `secretsmanager` (its region is not
  checked), and a 15-minute clock skew. There are no presigned URLs in this
  protocol. A request body larger than 1 MiB is refused. A signature must
  cover `host`, `x-amz-date`, `x-amz-target` and every other `x-amz-*` header
  the request carries, its `SignedHeaders` must be as SigV4 specifies them
  (lowercase, sorted and unique), and it must carry a real SHA-256 of the
  body: `UNSIGNED-PAYLOAD` is rejected, since it would leave the body
  outside the signature and let a relay swap one operation's body for
  another's. The root key is a long-term one, so a request carrying a
  session token on it is refused with `UnrecognizedClientException`; session
  tokens are only accepted on the keys identity issued them for.
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

The end-to-end tests include cross-service ones that build
[identity](https://github.com/tulehq/identity) and
[accounts](https://github.com/tulehq/accounts) from their source and run
them beside secret-store. They expect the checkouts beside this one, as
`../identity` and `../accounts`; set `TULE_E2E_IDENTITY_DIR` and
`TULE_E2E_ACCOUNTS_DIR` to use others. A missing checkout fails the tests
rather than skipping them.

## License

[MIT](LICENSE)

package authz

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tule.dev/sigv4"

	"tule.dev/secret-store/internal/smapi"
)

// now is the clock aws:CurrentTime and aws:EpochTime are read from. It is a
// variable so a test can fix it.
var now = time.Now

// globalKeys returns the global condition keys ("AWS global condition context
// keys", IAM User Guide) the service knows for r, signed by p:
//
//   - aws:SourceIp, the address the connection came from. No forwarding
//     header is trusted, since nothing is expected in front of the service.
//   - aws:CurrentTime and aws:EpochTime, when the request was evaluated.
//   - aws:SecureTransport, whether the request came over TLS.
//   - aws:PrincipalAccount, the principal's account.
//   - aws:PrincipalArn: an IAM user's ARN, or for a role session the role's
//     ARN, arn:aws:iam::<account>:role/<name>. A role's path is not known to
//     the service, since identity reports only the session's ARN, so the
//     value has none, unlike AWS's.
//   - aws:username, an IAM user's name.
//   - aws:RequestedRegion, region, the store's own. On AWS the endpoint
//     fixes the region; here any signed region verifies, so the credential
//     scope's region is the caller's to choose and is never used.
//
// aws:userid is not supplied: for a user or role it is a unique ID identity
// does not report.
func globalKeys(r *http.Request, p sigv4.Principal, region string) map[string][]string {
	t := now().UTC()
	keys := map[string][]string{
		"aws:RequestedRegion": {region},
		"aws:CurrentTime":     {t.Format(time.RFC3339)},
		"aws:EpochTime":       {strconv.FormatInt(t.Unix(), 10)},
		"aws:SecureTransport": {strconv.FormatBool(r.TLS != nil)},
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		keys["aws:SourceIp"] = []string{host}
	}
	if p.AccountID != "" {
		keys["aws:PrincipalAccount"] = []string{p.AccountID}
	}
	if arn, ok := principalARN(p.ARN); ok {
		keys["aws:PrincipalArn"] = []string{arn}
	}
	if name, ok := userName(p.ARN); ok {
		keys["aws:username"] = []string{name}
	}
	return keys
}

// principalARN is aws:PrincipalArn for the caller arn: the role's ARN, without
// its path, for an assumed-role session
// (arn:<partition>:sts::<account>:assumed-role/<role>/<session>), and arn
// itself otherwise.
func principalARN(arn string) (string, bool) {
	fields := strings.SplitN(arn, ":", 6)
	if len(fields) != 6 || fields[0] != "arn" {
		return "", false
	}
	if fields[2] != "sts" {
		return arn, true
	}
	rest, ok := strings.CutPrefix(fields[5], "assumed-role/")
	if !ok {
		return "", false
	}
	role, _, ok := strings.Cut(rest, "/")
	if !ok || role == "" {
		return "", false
	}
	return "arn:" + fields[1] + ":iam::" + fields[4] + ":role/" + role, true
}

// userName is aws:username for an IAM user's ARN: the last element of its
// path and name.
func userName(arn string) (string, bool) {
	fields := strings.SplitN(arn, ":", 6)
	if len(fields) != 6 || fields[0] != "arn" || fields[2] != "iam" {
		return "", false
	}
	path, ok := strings.CutPrefix(fields[5], "user/")
	if !ok {
		return "", false
	}
	return path[strings.LastIndexByte(path, '/')+1:], true
}

// The bounds of the condition context one check evaluates. tule.dev/policy's
// cost grows with the context's size times the policies' (its README,
// "Matching cost"), and the context holds request values and a secret's
// tags, so it is capped. The bounds sit above what AWS lets a request carry:
// Secrets Manager allows 50 tags per secret, of keys up to 128 characters and
// values up to 256, and its longest string parameters, SecretId, Description
// and KmsKeyId, are 2048 characters. A key name is at most a tag key with
// its aws:ResourceTag/ or secretsmanager:ResourceTag/ prefix.
const (
	maxContextKeys  = 256
	maxKeyValues    = 64
	maxKeyNameLen   = 512
	maxKeyValueLen  = 4096
	maxContextBytes = 256 << 10
)

// capContext refuses a context beyond the bounds above. Dropping keys or
// values instead could switch a Deny off, so the request is refused with
// InvalidParameterException.
func capContext(keys map[string][]string) error {
	if len(keys) > maxContextKeys {
		return tooMuchContext("more than " + strconv.Itoa(maxContextKeys) + " condition keys")
	}
	total := 0
	for k, vals := range keys {
		if len(k) > maxKeyNameLen {
			return tooMuchContext("a condition key name longer than " +
				strconv.Itoa(maxKeyNameLen) + " bytes")
		}
		if len(vals) > maxKeyValues {
			return tooMuchContext("more than " + strconv.Itoa(maxKeyValues) + " values for " + k)
		}
		for _, v := range vals {
			if len(v) > maxKeyValueLen {
				return tooMuchContext("a value of " + k + " longer than " +
					strconv.Itoa(maxKeyValueLen) + " bytes")
			}
			total += len(k) + len(v)
		}
	}
	if total > maxContextBytes {
		return tooMuchContext("more than " + strconv.Itoa(maxContextBytes) +
			" bytes of condition context")
	}
	return nil
}

func tooMuchContext(what string) error {
	return smapi.ErrInvalidParameter("The request carries " + what +
		", more than this service evaluates against IAM policies.")
}

// TagKeys returns the request keys of tags being added: aws:RequestTag/<key>
// for each tag and aws:TagKeys for all of their keys. The caller refuses
// tags that repeat a key first (contracts.CheckTagKeys), so each
// aws:RequestTag key has one value.
func TagKeys(tags []smapi.Tag) map[string][]string {
	if len(tags) == 0 {
		return nil
	}
	keys := make(map[string][]string, len(tags)+1)
	names := make([]string, 0, len(tags))
	for _, t := range tags {
		keys["aws:RequestTag/"+t.Key] = []string{t.Value}
		names = append(names, t.Key)
	}
	keys["aws:TagKeys"] = names
	return keys
}

// SecretKeys returns the keys every check on an existing secret carries: its
// ARN as secretsmanager:SecretId, its tags as aws:ResourceTag/<key> and
// secretsmanager:ResourceTag/<key>, and the region as
// secretsmanager:SecretPrimaryRegion.
func (a *Authorizer) SecretKeys(arn string, tags map[string]string) map[string][]string {
	keys := make(map[string][]string, 2*len(tags)+2)
	keys["secretsmanager:SecretId"] = []string{arn}
	keys["secretsmanager:SecretPrimaryRegion"] = []string{a.region}
	for k, v := range tags {
		keys["aws:ResourceTag/"+k] = []string{v}
		keys["secretsmanager:ResourceTag/"+k] = []string{v}
	}
	return keys
}

// secretARNBase is what the ARN of every secret of the store starts with:
// its partition, region and account.
func (a *Authorizer) secretARNBase() string {
	return "arn:aws:secretsmanager:" + a.region + ":" + a.account + ":secret:"
}

// arnSuffixLen is the length of the random suffix of a secret's ARN.
const arnSuffixLen = 6

// SecretARN is the ARN a check on the secret name is evaluated on: the
// store's partition, region and account, the name, and the random suffix of
// storedARN, the ARN the store minted for it. It is rebuilt rather than
// taken from the store or the request, so a check is always on this store's
// resource.
func (a *Authorizer) SecretARN(name, storedARN string) (string, error) {
	if len(storedARN) < arnSuffixLen+1 || storedARN[len(storedARN)-arnSuffixLen-1] != '-' {
		return "", fmt.Errorf("authz: stored ARN %q of %s has no random suffix", storedARN, name)
	}
	return a.secretARNBase() + name + storedARN[len(storedARN)-arnSuffixLen-1:], nil
}

// MissingSecretARN is the ARN a check on a secret that does not exist is
// evaluated on: for a name, the secret's ARN without a suffix, since it has
// none; for an ARN of this store's partition, region and account, the ARN
// rebuilt from those and the rest of it. An ARN of any other partition,
// region or account names no secret here, and ok is false: the request is
// answered ResourceNotFoundException without being evaluated.
func (a *Authorizer) MissingSecretARN(secretID string) (arn string, ok bool) {
	if !strings.HasPrefix(secretID, "arn:") {
		return a.secretARNBase() + secretID, true
	}
	rest, ok := strings.CutPrefix(secretID, a.secretARNBase())
	if !ok || rest == "" {
		return "", false
	}
	return a.secretARNBase() + rest, true
}

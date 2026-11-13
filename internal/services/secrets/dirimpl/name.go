package dirimpl

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"

	"tule.dev/secret-store/internal/contracts"
)

// maxNameLen is the longest secret name Secrets Manager accepts.
const maxNameLen = 512

// arnSuffixLen is the length of the random suffix Secrets Manager appends to a
// secret's name in its ARN, which keeps the ARN of a recreated secret distinct
// from the ARN of the one it replaced.
const arnSuffixLen = 6

// arnSuffixAlphabet is what the random ARN suffix is drawn from. Secrets
// Manager's own suffixes are alphanumeric.
const arnSuffixAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// arnPrefix is what every secret ARN starts with, up to the region and
// account.
const arnPrefix = "arn:aws:secretsmanager:"

// validateName checks a name against the Secrets Manager naming rules: 1 to
// 512 characters of ASCII letters, digits, and "/_+=.@-".
func validateName(name string) error {
	if name == "" || len(name) > maxNameLen {
		return fmt.Errorf("%w: %q is not 1 to %d characters",
			contracts.ErrInvalidName, name, maxNameLen)
	}
	for i := range len(name) {
		if !isNameByte(name[i]) {
			return fmt.Errorf("%w: %q contains %q",
				contracts.ErrInvalidName, name, name[i])
		}
	}
	return nil
}

func isNameByte(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	case c == '/', c == '_', c == '+', c == '=', c == '.', c == '@', c == '-':
		return true
	default:
		return false
	}
}

// fileName returns the file a secret is stored in. Secret names may contain
// "/", so they are hashed rather than used as paths; the name itself is
// recorded in the file.
func fileName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return path.Join(secretsDir, hex.EncodeToString(sum[:])+".json")
}

// NewSecretARN returns an ARN for a new secret: its name with a fresh random
// suffix, in the configured region and account. Nothing is stored; passed
// to CreateSecret, it becomes the secret's ARN.
func (s *Service) NewSecretARN(name string) (string, error) {
	suffix, err := randomSuffix()
	if err != nil {
		return "", err
	}
	return s.secretARNBase(name) + "-" + suffix, nil
}

// secretARNBase is the ARN of the secret name without its random suffix.
func (s *Service) secretARNBase(name string) string {
	return arnPrefix + s.settings.Region + ":" + s.settings.AccountID + ":secret:" + name
}

// newARN returns the ARN CreateSecret gives the secret in: the one the input
// carries, which must be one NewSecretARN could have returned for its name,
// or a fresh one.
func (s *Service) newARN(in contracts.CreateSecretInput) (string, error) {
	if in.ARN == "" {
		return s.NewSecretARN(in.Name)
	}
	base, ok := trimARNSuffix(in.ARN)
	if !ok || base != s.secretARNBase(in.Name) {
		return "", fmt.Errorf("secrets: ARN %q is not one minted for the name %q", in.ARN, in.Name)
	}
	return in.ARN, nil
}

func randomSuffix() (string, error) {
	buf := make([]byte, arnSuffixLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate an ARN suffix: %w", err)
	}
	for i, b := range buf {
		buf[i] = arnSuffixAlphabet[int(b)%len(arnSuffixAlphabet)]
	}
	return string(buf), nil
}

// idReading is how a secret identifier names a secret.
type idReading int

const (
	// byName: the identifier is the secret's name.
	byName idReading = iota
	// byFullARN: the identifier is exactly the secret's ARN.
	byFullARN
	// byPartialARN: the identifier is the secret's ARN without its suffix.
	byPartialARN
)

// readID returns the name a secret identifier refers to and how it refers
// to it, or ok false for an ARN with no secret name. A plain name refers to
// itself. An ARN whose last segment ends in a hyphen and six suffix
// characters is a full ARN, of the secret named the segment without them,
// and nothing else: Secrets Manager reads such an ARN as a full ARN, and
// says a partial ARN of a name shaped like that "might not" be found ("An
// AWS CLI or AWS SDK operation can't find my secret from a partial ARN",
// Secrets Manager User Guide, Troubleshooting). Any other ARN is a partial
// ARN of the secret named its last segment.
func readID(secretID string) (name string, how idReading, ok bool) {
	if !strings.HasPrefix(secretID, arnPrefix) {
		return secretID, byName, true
	}
	_, last, found := strings.Cut(secretID, ":secret:")
	if !found || last == "" {
		return "", 0, false
	}
	if trimmed, suffixed := trimARNSuffix(last); suffixed {
		return trimmed, byFullARN, true
	}
	return last, byPartialARN, true
}

// trimARNSuffix removes a trailing "-" plus arnSuffixLen suffix characters,
// reporting whether the last segment looked like one.
func trimARNSuffix(last string) (string, bool) {
	if len(last) < arnSuffixLen+2 {
		return "", false
	}
	head, suffix := last[:len(last)-arnSuffixLen], last[len(last)-arnSuffixLen:]
	if head[len(head)-1] != '-' {
		return "", false
	}
	for i := range len(suffix) {
		if !strings.ContainsRune(arnSuffixAlphabet, rune(suffix[i])) {
			return "", false
		}
	}
	return head[:len(head)-1], true
}

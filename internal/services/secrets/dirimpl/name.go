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

// mintARN returns the ARN of a new secret: its name with a fresh random
// suffix, in the configured region and account.
func (s *Service) mintARN(name string) (string, error) {
	suffix, err := randomSuffix()
	if err != nil {
		return "", err
	}
	return arnPrefix + s.settings.Region + ":" + s.settings.AccountID +
		":secret:" + name + "-" + suffix, nil
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

// candidateNames returns the names a secret identifier may refer to, in the
// order they should be tried. A plain name refers to itself. An ARN refers to
// the name in its last segment, either whole (a partial ARN, which Secrets
// Manager also accepts) or without its random suffix (a full ARN) -- both,
// because a name may itself end in something shaped like a suffix.
func candidateNames(secretID string) []string {
	if !strings.HasPrefix(secretID, arnPrefix) {
		return []string{secretID}
	}

	_, last, ok := strings.Cut(secretID, ":secret:")
	if !ok || last == "" {
		return nil
	}

	names := []string{last}
	if trimmed, found := trimARNSuffix(last); found {
		names = append(names, trimmed)
	}
	return names
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

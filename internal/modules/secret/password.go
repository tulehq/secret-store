package secret

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/smapi"
)

// GetRandomPassword's parameters, as the Secrets Manager API reference gives
// them.
const (
	// defaultPasswordLength is PasswordLength's default: "If you don't
	// include this parameter, the default length is 32 characters."
	defaultPasswordLength = 32
	// minPasswordLength and maxPasswordLength are PasswordLength's "Valid
	// Range: Minimum value of 1. Maximum value of 4096."
	minPasswordLength = 1
	maxPasswordLength = 4096
	// maxExcludeCharactersLen is ExcludeCharacters' "Maximum length of
	// 4096". It counts characters, not bytes.
	maxExcludeCharactersLen = 4096
)

// The character types a password is drawn from. punctuation is the set
// ExcludePunctuation names: "! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [
// \ ] ^ _ ` { | } ~".
const (
	uppercase   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowercase   = "abcdefghijklmnopqrstuvwxyz"
	digits      = "0123456789"
	punctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	space       = " "
)

func (m *Module) getRandomPassword(ctx gas.Context) error {
	req, err := decode[smapi.GetRandomPasswordRequest](ctx)
	if err != nil {
		return err
	}
	spec, err := passwordSpecOf(req)
	if err != nil {
		return err
	}
	// The reference gives the action no resource type, and it reads nothing
	// of the store's, so it is checked on "*" as on the caller's own account.
	if err = m.authorizeAll(ctx, "GetRandomPassword", "secretsmanager:GetRandomPassword",
		true); err != nil {
		return err
	}

	password, err := spec.generate(rand.Reader)
	if err != nil {
		return err
	}
	return smapi.Write(ctx, smapi.GetRandomPasswordResponse{RandomPassword: password})
}

// passwordSpec is what a password is drawn from: its length, the alphabet
// every position may take, and, when RequireEachIncludedType holds, the
// character types each of which it must contain at least once.
type passwordSpec struct {
	alphabet string
	required []string
	length   int
}

// passwordSpecOf validates req and returns the password it asks for.
//
// ExcludeCharacters is removed from every type, and a type left with no
// characters is not included: RequireEachIncludedType then asks for none of
// it, rather than failing a request whose exclusions remove a type outright.
// The API reference does not say which it does. The space IncludeSpace adds
// is never required: the reference's RequireEachIncludedType names "one
// upper and lowercase letter, one number, and one punctuation" only.
func passwordSpecOf(req smapi.GetRandomPasswordRequest) (passwordSpec, error) {
	length := int64(defaultPasswordLength)
	if req.PasswordLength != nil {
		length = *req.PasswordLength
	}
	// The range is the model's Valid Range, so a value outside it is a
	// model validation error, as ErrTooLong answers a model length.
	switch {
	case length < minPasswordLength:
		return passwordSpec{}, smapi.ErrTooSmall("passwordLength", length, minPasswordLength)
	case length > maxPasswordLength:
		return passwordSpec{}, smapi.ErrTooLarge("passwordLength", length, maxPasswordLength)
	}
	if utf8.RuneCountInString(req.ExcludeCharacters) > maxExcludeCharactersLen {
		return passwordSpec{}, smapi.ErrTooLong(
			"excludeCharacters", req.ExcludeCharacters, maxExcludeCharactersLen)
	}

	types, alphabet := passwordTypes(req)
	spec := passwordSpec{length: int(length), alphabet: alphabet}
	if spec.alphabet == "" {
		return passwordSpec{}, smapi.ErrInvalidParameter(
			"The password options exclude every character; include at least one character type.")
	}
	if req.RequireEachIncludedType == nil || *req.RequireEachIncludedType {
		spec.required = types
	}
	if len(spec.required) > spec.length {
		return passwordSpec{}, smapi.ErrInvalidParameter(fmt.Sprintf(
			"PasswordLength %d is too short to include each of the %d included character types.",
			spec.length, len(spec.required)))
	}
	return spec, nil
}

// passwordTypes returns the character types req includes, each without
// ExcludeCharacters and only when any of it is left, and the alphabet of
// them all, with the space when IncludeSpace asks for it.
func passwordTypes(req smapi.GetRandomPasswordRequest) ([]string, string) {
	without := func(chars string) string {
		return strings.Map(func(r rune) rune {
			if strings.ContainsRune(req.ExcludeCharacters, r) {
				return -1
			}
			return r
		}, chars)
	}

	var types []string
	for _, t := range []struct {
		chars    string
		excluded bool
	}{
		{uppercase, req.ExcludeUppercase},
		{lowercase, req.ExcludeLowercase},
		{digits, req.ExcludeNumbers},
		{punctuation, req.ExcludePunctuation},
	} {
		if chars := without(t.chars); !t.excluded && chars != "" {
			types = append(types, chars)
		}
	}

	alphabet := strings.Join(types, "")
	if req.IncludeSpace {
		alphabet += without(space)
	}
	return types, alphabet
}

// generate draws a password from random: one character of each required
// type, the rest from the whole alphabet, each chosen uniformly, then, when
// any were required, shuffled uniformly so they may land anywhere. Every
// character is ASCII, so the password is built byte by byte.
func (s passwordSpec) generate(random io.Reader) (string, error) {
	password := make([]byte, s.length)
	for i := range password {
		chars := s.alphabet
		if i < len(s.required) {
			chars = s.required[i]
		}
		n, err := uniform(random, len(chars))
		if err != nil {
			return "", err
		}
		password[i] = chars[n]
	}

	if len(s.required) == 0 {
		return string(password), nil
	}
	// Fisher-Yates: position i swaps with one chosen uniformly from 0..i.
	for i := len(password) - 1; i > 0; i-- {
		j, err := uniform(random, i+1)
		if err != nil {
			return "", err
		}
		password[i], password[j] = password[j], password[i]
	}
	return string(password), nil
}

// uniform returns an integer in [0, n), every one equally likely, from four
// bytes of random at a time. A draw at or above the largest multiple of n
// no greater than 2^32 is discarded and drawn again, so no value is favored the way
// taking a remainder of the whole range would favor the low ones.
func uniform(random io.Reader, n int) (int, error) {
	if n <= 0 || n > math.MaxUint32 {
		return 0, fmt.Errorf("no uniform draw over %d values", n)
	}
	const draws = uint64(math.MaxUint32) + 1
	limit := draws - draws%uint64(n)
	var buf [4]byte
	for {
		if _, err := io.ReadFull(random, buf[:]); err != nil {
			return 0, fmt.Errorf("read random bytes: %w", err)
		}
		if v := binary.BigEndian.Uint32(buf[:]); uint64(v) < limit {
			return int(v) % n, nil
		}
	}
}

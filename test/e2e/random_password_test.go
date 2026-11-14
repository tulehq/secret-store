//go:build e2e

package e2e

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// The character types GetRandomPassword draws from; punctuation is the set
// the API reference lists for ExcludePunctuation.
const (
	upperChars       = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars       = "abcdefghijklmnopqrstuvwxyz"
	digitChars       = "0123456789"
	punctuationChars = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
)

func randomPassword(t *testing.T, c *awssm.Client, in *awssm.GetRandomPasswordInput) string {
	t.Helper()
	out, err := c.GetRandomPassword(t.Context(), in)
	requireNoErr(t, err, "get random password")
	return aws.ToString(out.RandomPassword)
}

// requireDrawnFrom fails unless every character of password is in alphabet
// and each of types appears in it.
func requireDrawnFrom(t *testing.T, password, alphabet string, types ...string) {
	t.Helper()
	for _, r := range password {
		if !strings.ContainsRune(alphabet, r) {
			t.Fatalf("password %q has %q, outside %q", password, r, alphabet)
		}
	}
	for _, chars := range types {
		if !strings.ContainsAny(password, chars) {
			t.Fatalf("password %q has none of %q", password, chars)
		}
	}
}

func TestGetRandomPasswordDefaults(t *testing.T) {
	c := newClient(t)

	// 32 characters, with at least one of each type and no space.
	password := randomPassword(t, c, &awssm.GetRandomPasswordInput{})
	requireEqual(t, len(password), 32, "default length")
	all := upperChars + lowerChars + digitChars + punctuationChars
	requireDrawnFrom(t, password, all, upperChars, lowerChars, digitChars, punctuationChars)

	// Two calls do not repeat a password.
	if again := randomPassword(t, c, &awssm.GetRandomPasswordInput{}); again == password {
		t.Fatalf("two calls returned the same password %q", password)
	}
}

func TestGetRandomPasswordOptions(t *testing.T) {
	c := newClient(t)

	password := randomPassword(t, c, &awssm.GetRandomPasswordInput{
		PasswordLength:     aws.Int64(4096),
		ExcludePunctuation: aws.Bool(true),
		ExcludeNumbers:     aws.Bool(true),
		ExcludeCharacters:  aws.String("abcXYZ"),
		IncludeSpace:       aws.Bool(true),
	})
	requireEqual(t, len(password), 4096, "length")
	requireDrawnFrom(t, password,
		"defghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW ",
		"defghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVW", " ")

	password = randomPassword(t, c, &awssm.GetRandomPasswordInput{
		PasswordLength:   aws.Int64(64),
		ExcludeUppercase: aws.Bool(true),
		ExcludeLowercase: aws.Bool(true),
	})
	requireEqual(t, len(password), 64, "digits and punctuation length")
	requireDrawnFrom(t, password, digitChars+punctuationChars, digitChars, punctuationChars)

	// One character is enough without RequireEachIncludedType.
	password = randomPassword(t, c, &awssm.GetRandomPasswordInput{
		PasswordLength:          aws.Int64(1),
		RequireEachIncludedType: aws.Bool(false),
	})
	requireEqual(t, len(password), 1, "single character length")
}

func TestGetRandomPasswordErrors(t *testing.T) {
	c := clientFor(startServer(t, nil), func(o *awssm.Options) { o.RetryMaxAttempts = 1 })

	tests := map[string]*awssm.GetRandomPasswordInput{
		"every type excluded": {
			ExcludeUppercase: aws.Bool(true), ExcludeLowercase: aws.Bool(true),
			ExcludeNumbers: aws.Bool(true), ExcludePunctuation: aws.Bool(true),
		},
		"every character excluded": {
			ExcludeCharacters: aws.String(upperChars + lowerChars + digitChars + punctuationChars),
		},
		// Four types are required by default; three positions cannot hold
		// them.
		"too short for each type": {PasswordLength: aws.Int64(3)},
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := c.GetRandomPassword(t.Context(), in)
			requireAs[*smtypes.InvalidParameterException](t, err)
		})
	}

	// Model constraints are answered ValidationException.
	for name, in := range map[string]*awssm.GetRandomPasswordInput{
		"PasswordLength 0":    {PasswordLength: aws.Int64(0)},
		"PasswordLength 4097": {PasswordLength: aws.Int64(4097)},
		"ExcludeCharacters over 4096 characters": {
			ExcludeCharacters: aws.String(strings.Repeat("a", 4097)),
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.GetRandomPassword(t.Context(), in)
			requireCode(t, err, "ValidationException")
		})
	}
}

func TestGetRandomPasswordAcrossAccountsNeedsOnlyTheIdentityAllow(t *testing.T) {
	f := newCrossAccountFixture(t)

	// Without an identity Allow, another account's principal is denied, on
	// "*" and with the identity-based message: no resource policy is
	// involved.
	_, err := f.partner.GetRandomPassword(t.Context(), &awssm.GetRandomPasswordInput{})
	requireDenied(t, err, implicitDeny(f.partnerARN, "secretsmanager:GetRandomPassword", "*"))

	// With one, it is served: the action acts on no secret of the store's.
	f.putPartnerPolicy(t, allowDoc([]string{"secretsmanager:GetRandomPassword"}, "*"))
	requireEqual(t, len(randomPassword(t, f.partner, &awssm.GetRandomPasswordInput{})), 32,
		"partner's password length")
}

func TestGetRandomPasswordIsAuthorizedOnAllResources(t *testing.T) {
	f := newPolicyFixture(t)

	// Without a policy the action is denied, on "*": it acts on no secret.
	_, err := f.dev.GetRandomPassword(t.Context(), &awssm.GetRandomPasswordInput{})
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:GetRandomPassword", "*"))

	// Another action's grant does not cover it.
	putDevPolicy(t, f.ic, allowDoc([]string{"secretsmanager:GetSecretValue"}, "*"))
	_, err = f.dev.GetRandomPassword(t.Context(), &awssm.GetRandomPasswordInput{})
	requireDenied(t, err, implicitDeny(devARN, "secretsmanager:GetRandomPassword", "*"))

	putDevPolicy(t, f.ic, allowDoc([]string{"secretsmanager:GetRandomPassword"}, "*"))
	password := randomPassword(t, f.dev, &awssm.GetRandomPasswordInput{
		PasswordLength: aws.Int64(20),
	})
	requireEqual(t, len(password), 20, "allowed user's password length")

	// An explicit deny beats the allow.
	putDevPolicy(t, f.ic, policyDoc(
		statement{
			Effect: "Allow", Action: []string{"secretsmanager:GetRandomPassword"},
			Resource: []string{"*"},
		},
		statement{
			Effect: "Deny", Action: []string{"secretsmanager:GetRandomPassword"},
			Resource: []string{"*"},
		},
	))
	_, err = f.dev.GetRandomPassword(t.Context(), &awssm.GetRandomPasswordInput{})
	requireDenied(t, err, explicitDeny(devARN, "secretsmanager:GetRandomPassword", "*"))

	// The root key is never evaluated.
	requireEqual(t, len(randomPassword(t, f.root, &awssm.GetRandomPasswordInput{})), 32,
		"root's password length")
}

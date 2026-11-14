package secret

import (
	"bytes"
	"crypto/rand"
	"errors"
	mathrand "math/rand/v2"
	"strings"
	"testing"

	"tule.dev/secret-store/internal/smapi"
)

// generated returns a password req asks for, drawn from crypto/rand.
func generated(t *testing.T, req smapi.GetRandomPasswordRequest) string {
	t.Helper()
	spec, err := passwordSpecOf(req)
	if err != nil {
		t.Fatalf("spec of %+v: %v", req, err)
	}
	password, err := spec.generate(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return password
}

// seeded is a deterministic random source, so the statistical tests give
// the same answer on every run.
func seeded() *mathrand.ChaCha8 {
	return mathrand.NewChaCha8([32]byte{'t', 'u', 'l', 'e'})
}

func ref[T any](v T) *T { return &v }

func requireOnly(t *testing.T, password, alphabet string) {
	t.Helper()
	for _, r := range password {
		if !strings.ContainsRune(alphabet, r) {
			t.Fatalf("password %q has %q, outside %q", password, r, alphabet)
		}
	}
}

func TestPasswordPunctuationIsTheReferencesSet(t *testing.T) {
	// ExcludePunctuation, API reference: the 32 printable ASCII characters
	// that are neither letters, digits nor space.
	want := "! \" # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \\ ] ^ _ ` { | } ~"
	if got := strings.Join(strings.Split(punctuation, ""), " "); got != want {
		t.Fatalf("punctuation = %s, want %s", got, want)
	}
}

func TestPasswordLengthDefaultsTo32AndIsHonoredAtItsBounds(t *testing.T) {
	if got := len(generated(t, smapi.GetRandomPasswordRequest{})); got != 32 {
		t.Fatalf("default length = %d, want 32", got)
	}
	for _, n := range []int64{1, 4, 4096} {
		req := smapi.GetRandomPasswordRequest{PasswordLength: ref(n)}
		if n == 1 {
			// One position cannot hold one of each of four types.
			req.RequireEachIncludedType = ref(false)
		}
		if got := len(generated(t, req)); int64(got) != n {
			t.Fatalf("length = %d, want %d", got, n)
		}
	}
}

func TestPasswordDefaultUsesEveryTypeButSpace(t *testing.T) {
	password := generated(t, smapi.GetRandomPasswordRequest{PasswordLength: ref(int64(4096))})
	requireOnly(t, password, uppercase+lowercase+digits+punctuation)
	for _, chars := range []string{uppercase, lowercase, digits, punctuation} {
		if !strings.ContainsAny(password, chars) {
			t.Fatalf("password has none of %q", chars)
		}
	}
}

func TestPasswordExclusionFlagsRemoveTheirType(t *testing.T) {
	long := ref(int64(4096))
	tests := map[string]struct {
		want string
		req  smapi.GetRandomPasswordRequest
	}{
		"ExcludeUppercase": {
			want: lowercase + digits + punctuation,
			req:  smapi.GetRandomPasswordRequest{PasswordLength: long, ExcludeUppercase: true},
		},
		"ExcludeLowercase": {
			want: uppercase + digits + punctuation,
			req:  smapi.GetRandomPasswordRequest{PasswordLength: long, ExcludeLowercase: true},
		},
		"ExcludeNumbers": {
			want: uppercase + lowercase + punctuation,
			req:  smapi.GetRandomPasswordRequest{PasswordLength: long, ExcludeNumbers: true},
		},
		"ExcludePunctuation": {
			want: uppercase + lowercase + digits,
			req:  smapi.GetRandomPasswordRequest{PasswordLength: long, ExcludePunctuation: true},
		},
		"IncludeSpace": {
			want: uppercase + lowercase + digits + punctuation + space,
			req:  smapi.GetRandomPasswordRequest{PasswordLength: long, IncludeSpace: true},
		},
		"ExcludeCharacters": {
			want: "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ123456789" +
				"#$%&'()*+,-./:;<=>?@[]^_`{|}~",
			req: smapi.GetRandomPasswordRequest{
				PasswordLength: long, ExcludeCharacters: "aeiouAEIOU0!\\\"",
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			password := generated(t, tt.req)
			requireOnly(t, password, tt.want)
			// 4096 draws from fewer than 100 characters miss one with
			// a chance below 1e-17, so every allowed character appears.
			for _, r := range tt.want {
				if !strings.ContainsRune(password, r) {
					t.Fatalf("password never has %q", r)
				}
			}
		})
	}
}

func TestPasswordIncludeSpaceIsNotARequiredType(t *testing.T) {
	// With every type excluded only the space is left, which
	// RequireEachIncludedType does not ask for, so length 1 works.
	req := smapi.GetRandomPasswordRequest{
		PasswordLength: ref(int64(1)), IncludeSpace: true, ExcludeUppercase: true,
		ExcludeLowercase: true, ExcludeNumbers: true, ExcludePunctuation: true,
	}
	if got := generated(t, req); got != " " {
		t.Fatalf("password = %q, want a single space", got)
	}
	// ExcludeCharacters removes the space IncludeSpace adds.
	req.ExcludeCharacters = " "
	_, err := passwordSpecOf(req)
	requireAPIError(t, err, smapi.TypeInvalidParameter)
}

func TestPasswordRequireEachIncludedType(t *testing.T) {
	types := []string{uppercase, lowercase, digits, punctuation}

	// The default requires each type, so every 4-character password has
	// exactly one of each.
	for range 200 {
		password := generated(t, smapi.GetRandomPasswordRequest{PasswordLength: ref(int64(4))})
		for _, chars := range types {
			if !strings.ContainsAny(password, chars) {
				t.Fatalf("password %q has none of %q", password, chars)
			}
		}
	}

	// Without it, short passwords regularly miss a type: 200 4-character
	// passwords all holding every type would happen with a chance below
	// 1e-40.
	missed := false
	for range 200 {
		password := generated(t, smapi.GetRandomPasswordRequest{
			PasswordLength: ref(int64(4)), RequireEachIncludedType: ref(false),
		})
		for _, chars := range types {
			if !strings.ContainsAny(password, chars) {
				missed = true
			}
		}
	}
	if !missed {
		t.Fatal("RequireEachIncludedType false still put every type in every password")
	}
}

func TestPasswordATypeExcludeCharactersEmptiesIsNotRequired(t *testing.T) {
	// Every digit excluded by character: digits are no longer an included
	// type, so three positions hold the other three types.
	password := generated(t, smapi.GetRandomPasswordRequest{
		PasswordLength: ref(int64(3)), ExcludeCharacters: digits,
	})
	requireOnly(t, password, uppercase+lowercase+punctuation)
	for _, chars := range []string{uppercase, lowercase, punctuation} {
		if !strings.ContainsAny(password, chars) {
			t.Fatalf("password %q has none of %q", password, chars)
		}
	}
}

func TestPasswordOptionErrors(t *testing.T) {
	all := smapi.GetRandomPasswordRequest{
		ExcludeUppercase: true, ExcludeLowercase: true,
		ExcludeNumbers: true, ExcludePunctuation: true,
	}
	invalid := map[string]smapi.GetRandomPasswordRequest{
		"every type excluded": all,
		"every character excluded": {
			ExcludeCharacters: uppercase + lowercase + digits + punctuation,
		},
		"too short for each type": {PasswordLength: ref(int64(3))},
	}
	for name, req := range invalid {
		t.Run(name, func(t *testing.T) {
			_, err := passwordSpecOf(req)
			requireAPIError(t, err, smapi.TypeInvalidParameter)
		})
	}

	_, err := passwordSpecOf(smapi.GetRandomPasswordRequest{
		ExcludeCharacters: strings.Repeat("é", 4097),
	})
	requireAPIError(t, err, smapi.TypeValidation)

	// PasswordLength's Valid Range is the model's, answered in the model
	// validation form.
	outOfRange := map[int64]string{
		0: "1 validation error detected: Value '0' at 'passwordLength' failed to satisfy " +
			"constraint: Member must have value greater than or equal to 1",
		-1: "1 validation error detected: Value '-1' at 'passwordLength' failed to satisfy " +
			"constraint: Member must have value greater than or equal to 1",
		4097: "1 validation error detected: Value '4097' at 'passwordLength' failed to " +
			"satisfy constraint: Member must have value less than or equal to 4096",
	}
	for n, msg := range outOfRange {
		_, err = passwordSpecOf(smapi.GetRandomPasswordRequest{PasswordLength: ref(n)})
		requireAPIError(t, err, smapi.TypeValidation)
		var apiErr *smapi.Error
		if errors.As(err, &apiErr) && apiErr.Message != msg {
			t.Fatalf("PasswordLength %d: message %q, want %q", n, apiErr.Message, msg)
		}
	}

	// The limit counts characters: 4096 two-byte characters are allowed.
	_, err = passwordSpecOf(smapi.GetRandomPasswordRequest{
		ExcludeCharacters: strings.Repeat("é", 4096),
	})
	if err != nil {
		t.Fatalf("4096 characters of ExcludeCharacters: %v", err)
	}
	// Two positions hold the two types left.
	_, err = passwordSpecOf(smapi.GetRandomPasswordRequest{
		PasswordLength: ref(int64(2)), ExcludeUppercase: true, ExcludeLowercase: true,
	})
	if err != nil {
		t.Fatalf("length 2 with two types: %v", err)
	}
}

func requireAPIError(t *testing.T, err error, errType string) {
	t.Helper()
	var apiErr *smapi.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("want %s, got %v", errType, err)
	}
	if apiErr.Type != errType {
		t.Fatalf("want %s, got %s (%s)", errType, apiErr.Type, apiErr.Message)
	}
}

func TestPasswordCharactersAreUniform(t *testing.T) {
	// 2000 passwords of 32 characters over the 94 default characters,
	// counted against the 681 each expects. The source is seeded, so this
	// is the same draw every run; the bound is chi-squared's 0.1% critical
	// value for 93 degrees of freedom, which a uniform draw stays under.
	spec, err := passwordSpecOf(smapi.GetRandomPasswordRequest{RequireEachIncludedType: ref(false)})
	if err != nil {
		t.Fatal(err)
	}
	random := seeded()
	counts := map[byte]int{}
	const passwords = 2000
	for range passwords {
		password, gErr := spec.generate(random)
		if gErr != nil {
			t.Fatal(gErr)
		}
		for i := range len(password) {
			counts[password[i]]++
		}
	}

	if len(counts) != len(spec.alphabet) {
		t.Fatalf("%d distinct characters drawn, want %d", len(counts), len(spec.alphabet))
	}
	expected := float64(passwords*defaultPasswordLength) / float64(len(spec.alphabet))
	var chi2 float64
	for i := range len(spec.alphabet) {
		d := float64(counts[spec.alphabet[i]]) - expected
		chi2 += d * d / expected
	}
	if chi2 > 135.0 {
		t.Fatalf("chi-squared %.1f over 93 degrees of freedom: the draw is not uniform", chi2)
	}
}

func TestPasswordRequiredCharactersLandAnywhere(t *testing.T) {
	// Uppercase and digits, length 2, each required: every password is one
	// letter and one digit, and the shuffle puts the digit first half the
	// time. 10000 seeded draws give 5000 with a standard deviation of 50;
	// the bound is six of them.
	spec, err := passwordSpecOf(smapi.GetRandomPasswordRequest{
		PasswordLength: ref(int64(2)), ExcludeLowercase: true, ExcludePunctuation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	random := seeded()
	digitFirst := 0
	for range 10000 {
		password, gErr := spec.generate(random)
		if gErr != nil {
			t.Fatal(gErr)
		}
		first, second := password[0], password[1]
		isDigit := func(b byte) bool { return strings.IndexByte(digits, b) >= 0 }
		if isDigit(first) == isDigit(second) {
			t.Fatalf("password %q is not one letter and one digit", password)
		}
		if isDigit(first) {
			digitFirst++
		}
	}
	if digitFirst < 4700 || digitFirst > 5300 {
		t.Fatalf("the digit came first %d times in 10000, want about 5000", digitFirst)
	}
}

func TestUniformRejectsTheBiasedTail(t *testing.T) {
	// For n = 3 the largest multiple of 3 below 2^32 is 2^32 - 1, so
	// 0xFFFFFFFF would favor 0 if it were taken modulo 3. It is drawn
	// again instead, and the next draw, 5, gives 2.
	random := bytes.NewReader([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 5})
	got, err := uniform(random, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Fatalf("uniform = %d, want 2", got)
	}
}

func TestGenerateFailsWhenRandomnessDoes(t *testing.T) {
	spec, err := passwordSpecOf(smapi.GetRandomPasswordRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = spec.generate(bytes.NewReader([]byte{1, 2, 3})); err == nil {
		t.Fatal("generate succeeded on a source that ran dry")
	}
}

package secret

import (
	"errors"
	"strings"
	"testing"

	"tule.dev/secret-store/internal/smapi"
)

func TestDecodeReadsAnExactBody(t *testing.T) {
	body, err := decodeBody[smapi.TagResourceRequest](strings.NewReader(
		`{"SecretId":"app/db","Tags":[{"Key":"env","Value":"dev"}],"Unknown":{"x":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if body.SecretID != "app/db" || len(body.Tags) != 1 || body.Tags[0].Value != "dev" {
		t.Fatalf("decoded %+v", body)
	}
	if _, err = decodeBody[smapi.TagResourceRequest](strings.NewReader("")); err != nil {
		t.Fatalf("an empty body: %v", err)
	}
}

func TestDecodeRefusesAmbiguousBodies(t *testing.T) {
	// Each is a body encoding/json would read one way (the last member, or a
	// member matched regardless of case) where an exact reading differs. An
	// allowed env=dev must never be stored as env=prod.
	cases := map[string]string{
		"a repeated member": `{"SecretId":"app/db","SecretId":"app/other"}`,
		"a repeated member differing by case": `{"SecretId":"app/db",` +
			`"Tags":[{"Key":"env","Value":"dev"}],"tags":[{"Key":"env","Value":"prod"}]}`,
		"a repeated nested member": `{"SecretId":"app/db","Tags":[{"Key":"env","Value":"dev","Value":"prod"}]}`,
		"a member in another case": `{"secretid":"app/db","Tags":[]}`,
		"a nested member in another case": `{"SecretId":"app/db",` +
			`"Tags":[{"Key":"env","value":"prod"}]}`,
		"a repeated member inside an unknown one": `{"SecretId":"app/db","X":{"a":1,"A":2}}`,
	}
	for name, body := range cases {
		_, err := decodeBody[smapi.TagResourceRequest](strings.NewReader(body))
		var apiErr *smapi.Error
		if !errors.As(err, &apiErr) || apiErr.Type != smapi.TypeSerialization {
			t.Errorf("%s: want SerializationException, got %v", name, err)
		}
	}
}

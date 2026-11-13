package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/smapi"
)

// decode reads a request body into T. An empty body decodes to the zero
// value, and unknown members are ignored, as the AWS JSON protocol expects.
//
// The request is decoded once: the value decode returns is what the
// operation is authorized on and what it acts on, so the two cannot read the
// body differently. Bodies encoding/json would read in a way the AWS JSON
// protocol does not are refused before either sees them (see checkMembers).
func decode[T any](ctx gas.Context) (T, error) {
	return decodeBody[T](ctx.Request().Body)
}

func decodeBody[T any](r io.Reader) (T, error) {
	var body T
	raw, err := io.ReadAll(r)
	if err != nil {
		return body, smapi.ErrSerialization("The request body could not be read.")
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return body, nil
	}
	if err = checkMembers(json.NewDecoder(bytes.NewReader(raw)), reflect.TypeFor[T]()); err != nil {
		var ambiguous *ambiguousMember
		if errors.As(err, &ambiguous) {
			return body, smapi.ErrSerialization(ambiguous.Error())
		}
		return body, smapi.ErrSerialization("The request body is not valid JSON.")
	}
	if err = json.NewDecoder(bytes.NewReader(raw)).Decode(&body); err != nil {
		return body, smapi.ErrSerialization("The request body is not valid JSON.")
	}
	return body, nil
}

// ambiguousMember is a body member encoding/json and the AWS JSON protocol
// would read differently.
type ambiguousMember struct {
	msg string
}

func (e *ambiguousMember) Error() string { return e.msg }

// checkMembers walks the next JSON value of dec beside typ, the Go type it
// will be decoded into, and refuses the two readings encoding/json makes
// that a member-name-exact, single-valued reading would not:
//
//   - an object naming a member twice, regardless of case, where
//     encoding/json keeps the last;
//   - a member whose name matches one of typ's only regardless of case,
//     such as "secretId" for SecretId, which encoding/json accepts and
//     AWS's member names, matched exactly, would not.
//
// Neither is documented for Secrets Manager; refusing them is this
// service's choice, so no field can hold a value other than the one an
// exact reading gives. Members typ does not know are walked and ignored.
func checkMembers(dec *json.Decoder, typ reflect.Type) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch tok {
	case json.Delim('{'):
		return checkObject(dec, typ)
	case json.Delim('['):
		return checkArray(dec, typ)
	default:
		return nil
	}
}

func checkArray(dec *json.Decoder, typ reflect.Type) error {
	var elem reflect.Type
	if typ != nil && (typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array) {
		elem = typ.Elem()
	}
	for dec.More() {
		if err := checkMembers(dec, elem); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err //nolint:wrapcheck // the closing delimiter's read error, as read above
}

func checkObject(dec *json.Decoder, typ reflect.Type) error {
	seen := map[string]string{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		name, _ := tok.(string)
		if prev, dup := seen[strings.ToLower(name)]; dup {
			return &ambiguousMember{msg: fmt.Sprintf(
				"The request body names the member %q more than once (as %q and %q).",
				name, prev, name)}
		}
		seen[strings.ToLower(name)] = name

		field, err := memberType(typ, name)
		if err != nil {
			return err
		}
		if err = checkMembers(dec, field); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err //nolint:wrapcheck // the closing delimiter's read error, as read above
}

// memberType returns the type of typ's member name, nil for a member typ
// does not have, and fails for one it has only regardless of case.
func memberType(typ reflect.Type, name string) (reflect.Type, error) {
	if typ == nil || typ.Kind() != reflect.Struct {
		return nil, nil
	}
	for i := range typ.NumField() {
		f := typ.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		switch {
		case tag == name:
			return f.Type, nil
		case strings.EqualFold(tag, name):
			return nil, &ambiguousMember{msg: fmt.Sprintf(
				"The request body has the member %q, which is spelled %q.", name, tag)}
		}
	}
	return nil, nil
}

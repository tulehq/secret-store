// Package sigv4 verifies AWS Signature Version 4 on Secrets Manager requests.
//
// Secrets Manager speaks the AWS JSON protocol: every request is a POST with
// a small JSON body and an Authorization header, so verification is
// header-only. Unlike S3 there are no presigned URLs and no streaming
// (STREAMING-*) payloads to consider.
//
// The SDK signs the payload hash into the canonical request without sending
// it as a header, so the verifier hashes the body itself. The body is read
// into memory to do that, bounded by MaxBodySize, and handed to the handler
// from that buffer.
package sigv4

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"tule.dev/secret-store/internal/smapi"
)

const (
	algorithm = "AWS4-HMAC-SHA256"
	// unsignedPayload is the payload hash a client sends to say its body is
	// not covered by the signature. It is never accepted here.
	unsignedPayload = "UNSIGNED-PAYLOAD"
	amzDateFmt      = "20060102T150405Z"
	maxSkew         = 15 * time.Minute
	scopeSuffix     = "aws4_request"
)

// MaxBodySize bounds the request body the verifier will buffer. The largest
// legitimate request is a secret value, which Secrets Manager caps at 64 KiB,
// so this leaves ample room for the JSON around one.
const MaxBodySize = 1 << 20

// Credentials is the one access key the server accepts.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

// Verifier checks request signatures against Credentials.
type Verifier struct {
	now   func() time.Time
	creds Credentials
}

// NewVerifier returns a Verifier for creds.
func NewVerifier(creds Credentials) *Verifier {
	return &Verifier{creds: creds, now: time.Now}
}

// signed is what a request claims about its signature.
type signed struct {
	date          time.Time
	scope         string
	region        string
	service       string
	signature     string
	payloadHash   string
	signedHeaders []string
}

// Verify checks r's signature and returns an *smapi.Error when it is missing
// or wrong. It replaces r.Body with the buffered body it hashed, so a handler
// reads the same bytes the signature covers.
func (v *Verifier) Verify(r *http.Request) error {
	s, err := v.parseHeader(r)
	if err != nil {
		return err
	}

	body, err := readBody(r)
	if err != nil {
		return err
	}

	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	switch {
	case s.payloadHash == "":
		// The SDKs sign the hash without sending it, which is the usual case:
		// the body's own hash goes into the canonical request, so a body that
		// was changed in flight fails the signature below.
		s.payloadHash = hash
	case !isHexSHA256(s.payloadHash):
		// Anything else, UNSIGNED-PAYLOAD above all, asks for a signature
		// that covers no part of the body. Honoring it would let whoever
		// relays a signed request swap the body for another operation's.
		return incompleteSignature("x-amz-content-sha256 must be the hex SHA-256 of the " +
			"request body; " + unsignedPayload + " is not accepted.")
	case !strings.EqualFold(s.payloadHash, hash):
		return smapi.ErrInvalidParameter(
			"The provided 'x-amz-content-sha256' header does not match what was computed.")
	}

	want := v.signature(r, s)
	if !hmac.Equal([]byte(want), []byte(s.signature)) {
		return smapi.NewError(http.StatusForbidden, smapi.TypeInvalidSignature,
			"The request signature we calculated does not match the signature you provided. "+
				"Check your AWS Secret Access Key and signing method.")
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

// readBody reads up to MaxBodySize of r's body, rejecting anything longer
// rather than verifying a signature over a truncated body.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodySize+1))
	if err != nil {
		return nil, smapi.ErrInvalidParameter("The request body could not be read.")
	}
	if len(body) > MaxBodySize {
		return nil, smapi.NewError(http.StatusRequestEntityTooLarge, smapi.TypeInvalidParameter,
			"The request body is larger than this service accepts.")
	}
	return body, nil
}

func (v *Verifier) parseHeader(r *http.Request) (*signed, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, smapi.NewError(http.StatusForbidden, smapi.TypeMissingAuthToken,
			"Missing Authentication Token")
	}

	params, err := authParams(auth)
	if err != nil {
		return nil, err
	}

	date, err := time.Parse(amzDateFmt, r.Header.Get("X-Amz-Date"))
	if err != nil {
		return nil, incompleteSignature(
			"AWS authentication requires a valid X-Amz-Date header")
	}
	if skew := v.now().Sub(date); skew > maxSkew || skew < -maxSkew {
		return nil, smapi.NewError(http.StatusForbidden, smapi.TypeInvalidSignature,
			"Signature expired: the difference between the request time and the "+
				"current time is too large.")
	}

	s := &signed{
		date:          date,
		signature:     params["Signature"],
		payloadHash:   r.Header.Get("X-Amz-Content-Sha256"),
		signedHeaders: strings.Split(params["SignedHeaders"], ";"),
	}
	if err = requireSignedHeaders(s.signedHeaders); err != nil {
		return nil, err
	}
	if err = v.parseCredential(params["Credential"], s); err != nil {
		return nil, err
	}
	return s, nil
}

// requiredSignedHeaders are the headers a signature has to cover. Host ties a
// request to this server and X-Amz-Date to a point in time; X-Amz-Target names
// the operation, and left unsigned it would let whoever relays a signed read
// turn it into a delete, since the two carry the same body.
var requiredSignedHeaders = []string{"host", "x-amz-date", "x-amz-target"}

// requireSignedHeaders rejects a signature that leaves any of them out.
func requireSignedHeaders(signedHeaders []string) error {
	for _, want := range requiredSignedHeaders {
		if !slices.ContainsFunc(signedHeaders, func(got string) bool {
			return strings.EqualFold(strings.TrimSpace(got), want)
		}) {
			return incompleteSignature(
				"The request signature must cover the " + want + " header.")
		}
	}
	return nil
}

// authParams parses the Credential, SignedHeaders and Signature fields of a
// SigV4 Authorization header.
func authParams(auth string) (map[string]string, error) {
	fields, ok := strings.CutPrefix(auth, algorithm+" ")
	if !ok {
		return nil, incompleteSignature("The authorization mechanism you have provided " +
			"is not supported. Please use " + algorithm + ".")
	}

	params := make(map[string]string, 3)
	for f := range strings.SplitSeq(fields, ",") {
		k, val, _ := strings.Cut(strings.TrimSpace(f), "=")
		params[k] = val
	}
	if params["Credential"] == "" || params["SignedHeaders"] == "" || params["Signature"] == "" {
		return nil, incompleteSignature("The authorization header is malformed; it must " +
			"contain Credential, SignedHeaders and Signature.")
	}
	return params, nil
}

// parseCredential fills s from a "<key>/<date>/<region>/<service>/aws4_request"
// credential.
func (v *Verifier) parseCredential(cred string, s *signed) error {
	parts := strings.Split(cred, "/")
	if len(parts) != 5 || parts[4] != scopeSuffix {
		return incompleteSignature("The credential is malformed; expecting " +
			"\"<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request\".")
	}
	if parts[0] != v.creds.AccessKeyID {
		return smapi.NewError(http.StatusForbidden, smapi.TypeUnrecognizedClient,
			"The security token included in the request is invalid.")
	}
	if parts[1] != s.date.Format("20060102") {
		return incompleteSignature("The credential date does not match the request date.")
	}

	s.region, s.service = parts[2], parts[3]
	s.scope = strings.Join(parts[1:], "/")
	return nil
}

// signature computes the signature r should carry for the claims in s.
func (v *Verifier) signature(r *http.Request, s *signed) string {
	creq := strings.Join([]string{
		r.Method,
		canonicalURI(r.URL.Path),
		canonicalQuery(r.URL.Query()),
		canonicalHeaders(r, s.signedHeaders),
		strings.Join(s.signedHeaders, ";"),
		s.payloadHash,
	}, "\n")

	creqHash := sha256.Sum256([]byte(creq))
	toSign := strings.Join([]string{
		algorithm,
		s.date.Format(amzDateFmt),
		s.scope,
		hex.EncodeToString(creqHash[:]),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+v.creds.SecretAccessKey), s.date.Format("20060102"))
	key = hmacSHA256(key, s.region)
	key = hmacSHA256(key, s.service)
	key = hmacSHA256(key, scopeSuffix)

	return hex.EncodeToString(hmacSHA256(key, toSign))
}

func canonicalURI(p string) string {
	if p == "" {
		return "/"
	}
	return uriEncode(p, false)
}

// canonicalQuery sorts the query by name and then value, URI-encoding both.
func canonicalQuery(q url.Values) string {
	var pairs []string
	for k, vals := range q {
		for _, val := range vals {
			pairs = append(pairs, uriEncode(k, true)+"="+uriEncode(val, true))
		}
	}
	slices.Sort(pairs)
	return strings.Join(pairs, "&")
}

// canonicalHeaders lists the signed headers as "name:value\n" lines, with
// values trimmed and inner runs of spaces collapsed.
func canonicalHeaders(r *http.Request, names []string) string {
	var sb strings.Builder
	for _, name := range names {
		var val string
		switch vals := r.Header.Values(name); {
		case name == "host":
			val = r.Host
		case name == "content-length" && len(vals) == 0 && r.ContentLength >= 0:
			// net/http may keep the length only in r.ContentLength.
			val = strconv.FormatInt(r.ContentLength, 10)
		default:
			for i, x := range vals {
				vals[i] = strings.Join(strings.Fields(x), " ")
			}
			val = strings.Join(vals, ",")
		}
		sb.WriteString(name)
		sb.WriteByte(':')
		sb.WriteString(val)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// uriEncode percent-encodes everything but the RFC 3986 unreserved characters,
// and slashes unless encodeSlash is set.
func uriEncode(s string, encodeSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var sb strings.Builder
	for i := range len(s) {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9',
			c == '-', c == '_', c == '.', c == '~',
			c == '/' && !encodeSlash:
			sb.WriteByte(c)
		default:
			sb.WriteByte('%')
			sb.WriteByte(hexDigits[c>>4])
			sb.WriteByte(hexDigits[c&0xf])
		}
	}
	return sb.String()
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func isHexSHA256(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func incompleteSignature(msg string) error {
	return smapi.NewError(http.StatusForbidden, smapi.TypeIncompleteSig, msg)
}

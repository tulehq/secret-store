package dirimpl

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// newVersionID returns a fresh version ID. Secrets Manager version IDs are
// UUIDs, and a client request token may be used as one, so this generates a
// random version 4 UUID rather than a sequence number.
func newVersionID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("failed to generate a version ID: %w", err)
	}
	buf[6] = (buf[6] & 0x0f) | 0x40 // version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // RFC 4122 variant

	h := hex.EncodeToString(buf[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

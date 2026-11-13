package authz

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"

	"tule.dev/policy"
)

// maxCachedDocs bounds the parsed policy documents kept. Each is at most
// identity's 131,072-character document limit; a principal has a handful, so
// this covers many principals while holding memory to a known bound.
const maxCachedDocs = 1024

// docCache keeps parsed policy documents by the SHA-256 of their bytes, so a
// principal's policies are parsed once rather than on every request. When it
// is full the oldest entry goes. Documents that do not parse are not kept.
type docCache struct {
	docs  map[[sha256.Size]byte]*policy.Policy
	order [][sha256.Size]byte
	max   int
	mu    sync.Mutex
}

func newDocCache(maxDocs int) *docCache {
	return &docCache{docs: make(map[[sha256.Size]byte]*policy.Policy, maxDocs), max: maxDocs}
}

// parse returns the parsed form of every document, failing on the first that
// does not parse as an identity-based policy.
func (c *docCache) parse(docs []json.RawMessage) ([]*policy.Policy, error) {
	out := make([]*policy.Policy, 0, len(docs))
	for i, doc := range docs {
		p, err := c.get(doc)
		if err != nil {
			return nil, fmt.Errorf("policy %d: %w", i, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func (c *docCache) get(doc []byte) (*policy.Policy, error) {
	sum := sha256.Sum256(doc)

	c.mu.Lock()
	p, ok := c.docs[sum]
	c.mu.Unlock()
	if ok {
		return p, nil
	}

	p, err := policy.ParseIdentity(doc)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok = c.docs[sum]; !ok {
		if len(c.order) >= c.max {
			delete(c.docs, c.order[0])
			c.order = c.order[1:]
		}
		c.docs[sum] = p
		c.order = append(c.order, sum)
	}
	return p, nil
}

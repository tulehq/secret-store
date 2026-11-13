package authz

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"

	"tule.dev/policy"
)

// maxCachedDocs bounds the parsed policy documents kept in each cache. An
// identity policy is at most identity's 131,072-character document limit,
// and a principal has a handful; a secret's resource policy is at most
// 20,480 characters, and a secret has one. This covers many principals and
// secrets while holding memory to a known bound.
const maxCachedDocs = 1024

// docCache keeps parsed policy documents by the SHA-256 of their bytes, so a
// document is parsed once rather than on every request. When it is full the
// oldest entry goes. Documents that do not parse are not kept.
type docCache struct {
	docs  map[[sha256.Size]byte]*policy.Policy
	parse func([]byte) (*policy.Policy, error)
	order [][sha256.Size]byte
	max   int
	mu    sync.Mutex
}

// newDocCache returns a cache of at most maxDocs documents, each parsed with
// parse: policy.ParseIdentity for identity policies, policy.ParseResource
// for resource policies.
func newDocCache(maxDocs int, parse func([]byte) (*policy.Policy, error)) *docCache {
	return &docCache{
		docs:  make(map[[sha256.Size]byte]*policy.Policy, maxDocs),
		parse: parse,
		max:   maxDocs,
	}
}

// all returns the parsed form of every document, failing on the first that
// does not parse.
func (c *docCache) all(docs []json.RawMessage) ([]*policy.Policy, error) {
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

	p, err := c.parse(doc)
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

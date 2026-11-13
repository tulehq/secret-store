package secret

import (
	"slices"
	"testing"

	"tule.dev/secret-store/internal/authz"
)

func TestEveryRoutedOperationHasAMappingEntry(t *testing.T) {
	routes := (&Module{}).routes()

	for op := range routes {
		if _, ok := authz.Operations[op]; !ok {
			t.Errorf("%s is routed but has no entry in authz.Operations", op)
		}
		if slices.Contains(unserved, op) {
			t.Errorf("%s is both routed and listed as unserved", op)
		}
	}
	for op := range authz.Operations {
		if _, ok := routes[op]; !ok {
			t.Errorf("authz.Operations has an entry for %s, which is not routed", op)
		}
	}
}

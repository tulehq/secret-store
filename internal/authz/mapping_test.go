package authz

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// reference is the part of the Service Authorization Reference's JSON for
// Secrets Manager the mapping is checked against. testdata/secretsmanager.json
// is a copy of
// https://servicereference.us-east-1.amazonaws.com/v1/secretsmanager/secretsmanager.json
// (Version v1.5), fetched 2026-11-13.
type reference struct {
	Actions    []refAction
	Operations []refOperation
}

type refAction struct {
	Name                string
	ActionConditionKeys []string
	Resources           []struct{ Name string }
}

type refOperation struct {
	Name              string
	AuthorizedActions []struct{ Name, Service string }
}

func loadReference(t *testing.T) reference {
	t.Helper()
	raw, err := os.ReadFile("testdata/secretsmanager.json")
	if err != nil {
		t.Fatalf("read the reference: %v", err)
	}
	var ref reference
	if err = json.Unmarshal(raw, &ref); err != nil {
		t.Fatalf("decode the reference: %v", err)
	}
	if len(ref.Actions) == 0 || len(ref.Operations) == 0 {
		t.Fatal("the reference lists no actions or operations")
	}
	return ref
}

func TestEveryCheckIsAnActionOfTheReference(t *testing.T) {
	ref := loadReference(t)

	for op, checks := range Operations {
		if len(checks) == 0 {
			t.Errorf("%s has no checks", op)
			continue
		}
		if want := "secretsmanager:" + op; checks[0].Action != want {
			t.Errorf("%s: the first check is %s, want the operation's own action %s",
				op, checks[0].Action, want)
		}
		for _, c := range checks {
			checkAgainstReference(t, ref, op, c)
		}
	}
}

// checkAgainstReference checks c, a check of op, names an action of the
// reference, on that action's resource type, with keys the reference lists
// for it.
func checkAgainstReference(t *testing.T, ref reference, op string, c Check) {
	t.Helper()

	name, ok := strings.CutPrefix(c.Action, "secretsmanager:")
	if !ok {
		t.Errorf("%s: %s is not a secretsmanager action", op, c.Action)
		return
	}
	i := slices.IndexFunc(ref.Actions, func(a refAction) bool { return a.Name == name })
	if i < 0 {
		t.Errorf("%s: the reference has no action %s", op, c.Action)
		return
	}
	action := ref.Actions[i]

	if msg := resourceMismatch(action, c); msg != "" {
		t.Errorf("%s: %s %s", op, c.Action, msg)
	}

	for _, k := range c.Keys {
		if !slices.Contains(action.ActionConditionKeys, k) {
			t.Errorf("%s: the reference lists no key %s for %s", op, k, c.Action)
		}
	}
}

func TestEveryCheckIsAnActionTheReferenceAuthorizesForTheOperation(t *testing.T) {
	ref := loadReference(t)

	for op, checks := range Operations {
		i := slices.IndexFunc(ref.Operations, func(o refOperation) bool { return o.Name == op })
		if i < 0 {
			t.Errorf("the reference has no operation %s", op)
			continue
		}
		var authorized []string
		for _, a := range ref.Operations[i].AuthorizedActions {
			authorized = append(authorized, a.Service+":"+a.Name)
		}
		for _, c := range checks {
			if !slices.Contains(authorized, c.Action) {
				t.Errorf("%s: the reference does not authorize it as %s (it lists %v)",
					op, c.Action, authorized)
			}
		}
	}
}

// resourceMismatch says how c's resource differs from the one the reference
// gives its action, or "" when they agree.
func resourceMismatch(action refAction, c Check) string {
	onSecret := c.Resource == Secret || c.Resource == NewSecret
	switch {
	case len(action.Resources) == 0 && c.Resource != AllResources:
		return "has no resource type in the reference, so it is on *"
	case len(action.Resources) > 0 && !onSecret:
		return "is on a resource type in the reference, not on *"
	case len(action.Resources) > 0 && action.Resources[0].Name != "Secret":
		return "is on " + action.Resources[0].Name + ", not Secret"
	default:
		return ""
	}
}

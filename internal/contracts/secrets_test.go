package contracts

import (
	"context"
	"errors"
	"testing"
)

func TestTagKeyChecks(t *testing.T) {
	envs := []Tag{{Key: "Env", Value: "a"}, {Key: "env", Value: "b"}}
	if err := CheckTagKeys(envs); err != nil {
		t.Fatalf("keys differing by case are distinct: %v", err)
	}
	if err := CheckTagKeysFold(envs); !errors.Is(err, ErrDuplicateTagKeys) {
		t.Fatalf("CheckTagKeysFold: %v", err)
	}
	if err := CheckTagKeys(
		[]Tag{{Key: "env"}, {Key: "env"}},
	); !errors.Is(
		err,
		ErrDuplicateTagKeys,
	) {
		t.Fatalf("CheckTagKeys: %v", err)
	}

	stored := []Tag{{Key: "Env", Value: "a"}}
	if err := CheckTagKeysAgainst(
		[]Tag{{Key: "env"}},
		stored,
	); !errors.Is(
		err,
		ErrDuplicateTagKeys,
	) {
		t.Fatalf("a key differing from a stored one by case: %v", err)
	}
	if err := CheckTagKeysAgainst([]Tag{{Key: "Env"}, {Key: "team"}}, stored); err != nil {
		t.Fatalf("replacing a stored key, and a new one: %v", err)
	}
}

func TestRunCheckFailsClosed(t *testing.T) {
	ctx := context.Background()
	if err := RunCheck(ctx, nil); !errors.Is(err, ErrNoCheck) {
		t.Fatalf("no check: %v", err)
	}
	if err := RunCheck(WithCheck(ctx, nil), nil); !errors.Is(err, ErrNoCheck) {
		t.Fatalf("a nil check: %v", err)
	}
	if err := RunCheck(Unchecked(ctx), &SecretDetail{}); err != nil {
		t.Fatalf("unchecked: %v", err)
	}
	refused := errors.New("refused")
	if err := RunCheck(
		WithCheck(ctx, func(*SecretDetail) error { return refused }),
		nil,
	); !errors.Is(
		err,
		refused,
	) {
		t.Fatalf("a check: %v", err)
	}
}

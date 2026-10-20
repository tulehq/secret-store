package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/contracts"
)

// seedSecrets returns a ready hook that creates the secrets described by a
// JSON object, whose keys are secret names and whose values are their values:
// a string is stored as it is, anything else as its JSON. Secrets that already
// exist are left alone, so a restart on the same store keeps whatever the app
// wrote.
//
// Ready hooks run before the server listens, so a client never sees the store
// without its seeded secrets.
func seedSecrets(seed string) func(*gas.ServiceContainer) error {
	return func(sc *gas.ServiceContainer) error {
		if seed == "" {
			return nil
		}

		values, err := parseSeed(seed)
		if err != nil {
			return err
		}

		secrets, err := sc.Resolve[contracts.SecretsProvider]()
		if err != nil {
			return fmt.Errorf("app: failed to resolve the secret store: %w", err)
		}

		logger, err := sc.Resolve[gas.Logger]()
		if err != nil {
			return fmt.Errorf("app: failed to resolve the logger: %w", err)
		}

		for name, value := range values {
			if cErr := createSeed(secrets, logger, name, value); cErr != nil {
				return cErr
			}
		}
		return nil
	}
}

func parseSeed(seed string) (map[string]json.RawMessage, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal([]byte(seed), &values); err != nil {
		return nil, fmt.Errorf("app: TULE_Store_Seed is not a JSON object: %w", err)
	}
	return values, nil
}

// createSeed creates one seeded secret, leaving an existing secret of that
// name alone.
//
// A secret scheduled for deletion counts as existing. Nothing sweeps a
// scheduled deletion here, so treating it as absent would fail every restart
// from then on, with no way out but emptying the data directory; it is worth a
// warning rather than a refusal to start.
func createSeed(
	secrets contracts.SecretsProvider,
	logger gas.Logger,
	name string,
	value json.RawMessage,
) error {
	_, err := secrets.CreateSecret(context.Background(), contracts.CreateSecretInput{
		Name:        name,
		Description: "Seeded at startup from TULE_Store_Seed.",
		Payload:     contracts.Payload{String: seedValue(value)},
	})

	switch {
	case err == nil, errors.Is(err, contracts.ErrSecretExists):
		return nil
	case errors.Is(err, contracts.ErrSecretDeleted):
		logger.Warn("seeded secret is scheduled for deletion and was left as it is").
			Str("secret", name).Send()
		return nil
	default:
		return fmt.Errorf("app: failed to seed secret %q: %w", name, err)
	}
}

// seedValue renders one seeded value as the string the secret holds: a JSON
// string unquoted, anything else as the JSON it was written as, which is the
// shape a config provider expects of a secret holding several settings.
func seedValue(value json.RawMessage) *string {
	if unquoted, err := strconv.Unquote(string(value)); err == nil {
		return &unquoted
	}
	s := string(value)
	return &s
}

// Package dirimpl implements contracts.SecretsProvider on a local directory,
// storing one JSON file per secret.
//
// A secret file holds the secret's metadata and every version of its value,
// which is what makes the staging labels cheap to move: a label change is a
// rewrite of one file. Since a secret name may contain "/", the file is named
// after the hash of the name rather than the name itself, and the name is
// recorded inside.
//
// Nothing here encrypts anything. The files are plain JSON on a developer's
// disk, which is the point: a stand-in for Secrets Manager you can read with
// cat, not a secret store to keep production secrets in.
package dirimpl

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/contracts"
)

// secretsDir holds one file per secret, under the storage root.
const secretsDir = "secrets"

// filePerm is the mode of a secret file: readable only by the user the server
// runs as, since the files hold secret values in the clear.
const filePerm = 0o600

// defaultPageSize is how many items a list operation returns when the request
// does not ask for a page size. It matches the Secrets Manager default.
const defaultPageSize = 100

// maxPageSize is the largest page a list operation returns, whatever the
// request asks for. It matches the Secrets Manager limit.
const maxPageSize = 100

// Service stores secrets as JSON files under Settings.RootDir.
type Service struct {
	logger   gas.Logger
	settings *Settings
	root     *os.Root
	now      func() time.Time

	// mu serializes every operation. Each one is a read-modify-write of a
	// whole secret file, and a stand-in store serves one app's config, so a
	// single lock is simpler than a lock per secret and costs nothing here.
	mu sync.Mutex
}

var (
	_ contracts.SecretsProvider = (*Service)(nil)
	_ gas.Service               = (*Service)(nil)
	_ gas.ReadyReporter         = (*Service)(nil)
)

// NewService returns the constructor gas uses to build a Service from
// settings.
func NewService(settings *Settings) func(logger gas.Logger) *Service {
	return func(logger gas.Logger) *Service {
		return &Service{settings: settings, logger: logger, now: time.Now}
	}
}

// Name identifies the service to gas.
func (s *Service) Name() string {
	return "tule/services/secrets/dir"
}

// Init creates the storage root if needed and opens it.
func (s *Service) Init(context.Context) error {
	root, err := s.openRoot()
	if err != nil {
		return fmt.Errorf("%s: %w", s.Name(), err)
	}
	s.root = root
	return nil
}

// CheckReady reports whether the secrets directory can be read, which fails
// once the service is closed or the storage root goes away.
func (s *Service) CheckReady(context.Context) error {
	if _, err := s.root.Stat(secretsDir); err != nil {
		return fmt.Errorf("%s: %w", s.Name(), err)
	}
	return nil
}

// Close closes the storage root.
func (s *Service) Close(context.Context) error {
	if err := s.root.Close(); err != nil {
		return fmt.Errorf("%s: %w", s.Name(), err)
	}
	return nil
}

func (s *Service) openRoot() (*os.Root, error) {
	if err := os.MkdirAll(s.settings.RootDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create storage root: %w", err)
	}
	root, err := os.OpenRoot(s.settings.RootDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open storage root: %w", err)
	}
	if err = root.Mkdir(secretsDir, 0o700); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("failed to create %s in storage root: %w",
			secretsDir, err)
	}
	return root, nil
}

// pageSize clamps a requested page size to what the store serves.
func pageSize(requested int) int {
	switch {
	case requested <= 0:
		return defaultPageSize
	case requested > maxPageSize:
		return maxPageSize
	default:
		return requested
	}
}

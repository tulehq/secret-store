package dirimpl

// Settings configures a Service. RootDir is where the secrets are stored.
// Region and AccountID appear in the ARNs the store mints, so an app's
// expectations about them hold locally. Seed is a JSON object whose keys are
// secret names and whose values are their initial values, created at startup
// when they do not exist yet.
type Settings struct {
	RootDir   string `validate:"required"`
	Region    string `validate:"required"`
	AccountID string `validate:"required"`
	Seed      string
}

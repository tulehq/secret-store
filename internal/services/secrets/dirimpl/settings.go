package dirimpl

// Settings configures a Service. RootDir is where the secrets are stored.
// Region and AccountID appear in the ARNs the store mints, so an app's
// expectations about them hold locally. Seed is a JSON object whose keys are
// secret names and whose values are their initial values, created at startup
// when they do not exist yet.
//
// FunctionsEndpoint is not the store's: it is the functions service's base
// URL, through whose service-invoke endpoint the rotation service invokes
// rotation functions, or empty to leave rotation unserved. It is a setting
// of this section, TULE_Store_FunctionsEndpoint, as every Tule service puts
// the endpoints of the services it calls in its own section
// (TULE_Functions_QueuesEndpoint, TULE_Identity_AccountsEndpoint); the app
// reads it, and the store never does.
type Settings struct {
	RootDir           string `validate:"required"`
	Region            string `validate:"required"`
	AccountID         string `validate:"required"`
	Seed              string
	FunctionsEndpoint string
}

package app

import (
	"net/http"
	"os"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/config"
	gaszerolog "github.com/gasmod/gas/log/zerolog"
	"github.com/rs/zerolog"

	"tule.dev/secret-store/internal/httpx"
	"tule.dev/secret-store/internal/util/buildinfo"
)

// newLogger returns the logger for env. Logs go to the console and nowhere
// else: there is no shipping sink here until Tule has a logging service to
// ship to.
func newLogger(env config.Environment) (gas.Logger, error) {
	if env.IsTesting() {
		return &gas.NopLogger{}, nil
	}
	if env.IsProductionLike() {
		return newProdLogger()
	}
	return newDevLogger()
}

func newProdLogger() (gas.Logger, error) {
	out := zerolog.ConsoleWriter{Out: os.Stderr}

	zl := zerolog.New(out).Level(zerolog.WarnLevel).With().Timestamp().
		Str("app_ver", buildinfo.Version).Logger()

	return newZeroLogger(&zl)
}

func newDevLogger() (gas.Logger, error) {
	out := zerolog.ConsoleWriter{Out: os.Stderr}

	zl := zerolog.New(out).Level(zerolog.TraceLevel).With().Timestamp().
		Str("app_ver", buildinfo.Version).Logger()

	return newZeroLogger(&zl)
}

// newZeroLogger returns a gas.Logger over zl. It returns a nil interface
// rather than a nil *gaszerolog.Logger when it fails.
func newZeroLogger(zl *zerolog.Logger) (gas.Logger, error) {
	l, err := gaszerolog.New(gaszerolog.WithLogger(zl))()
	if err != nil {
		return nil, err
	}
	return l, nil
}

func resolveRequestLogger(l gas.Logger) httpx.RequestLogger {
	return l.With().Logger()
}

func withRequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger, err := gas.ResolveFromRequestScope[httpx.RequestLogger](r)
		if err != nil {
			return
		}

		ctx := gas.WithLogger(r.Context(), logger)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

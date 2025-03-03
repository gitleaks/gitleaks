package logging

import (
	"os"

	"github.com/rs/zerolog"
)

var Logger zerolog.Logger

func init() {
	// send all logs to stdout
	Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		Level(zerolog.InfoLevel).
		With().Timestamp().Logger()
}

func With() zerolog.Context {
	return Logger.With()
}

func Trace() *zerolog.Event {
	return Logger.Trace()
}

func Debug() *zerolog.Event {
	return Logger.Debug()
}
func Info() *zerolog.Event {
	return Logger.Info()
}
func Warn() *zerolog.Event {
	return Logger.Warn()
}

func Error() *zerolog.Event {
	return Logger.Error()
}

func Err(err error) *zerolog.Event {
	return Logger.Err(err)
}

func Fatal() *zerolog.Event {
	return Logger.Fatal()
}

func Panic() *zerolog.Event {
	return Logger.Panic()
}

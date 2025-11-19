package cmd

import (
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/sources"
)

const fetchURLPatternDescription = `
scan URL values in the JSON in matching paths:
- the full value must be a URL (i.e. URLs located just somewhere in a string will be skipped)
- currently only HTTP(S) URLs and GET requests are supported
- paths are formatted like file paths where keys and array indices are path elements
- finding paths will be reported as the path to the URL in the JSON
- * acts as a wildcard within single path elements (i.e. '[^/]*' in regex)
- ** acts as a wildcard across multiple path elements (i.e '.*' in regex)
`

func init() {
	rootCmd.AddCommand(jsonCmd)
	jsonCmd.Flags().StringSliceP("http-header", "H", []string{}, "HTTP header used in fetch-url-pattern requests (format 'Header: value')")
	jsonCmd.Flags().StringSlice("fetch-url-pattern", []string{}, fetchURLPatternDescription)
}

var jsonCmd = &cobra.Command{
	Use:   "json [flags]",
	Short: "detect secrets in JSON text from stdin",
	Run:   runJSON,
}

func runJSON(cmd *cobra.Command, args []string) {
	// start timer
	start := time.Now()

	// setup config (aka, the thing that defines rules)
	initConfig(".")
	initDiagnostics()

	cfg := Config(cmd)

	// create detector
	detector := Detector(cmd, cfg, "")

	// parse flags
	exitCode := mustGetIntFlag(cmd, "exit-code")
	httpHeaderArgs := mustGetStringSliceFlag(cmd, "http-header")
	fetchURLPatterns := mustGetStringSliceFlag(cmd, "fetch-url-pattern")

	jsonText, err := io.ReadAll(os.Stdin)
	if err != nil {
		logging.Fatal().Err(err).Msg("could not read all of stdin")
	}

	findings, err := detector.DetectSource(
		cmd.Context(),
		&sources.JSON{
			Config:           &cfg,
			FetchURLPatterns: fetchURLPatterns,
			MaxArchiveDepth:  detector.MaxArchiveDepth,
			HTTPHeader:       parseHTTPHeaderArgs(httpHeaderArgs),
			Text:             jsonText,
		},
	)

	if err != nil {
		// don't exit on error, just log it
		logging.Error().Err(err).Msg("failed to scan JSON text")
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}

package cmd

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func init() {
	rootCmd.AddCommand(urlCmd)
	urlCmd.Flags().StringP("http-method", "X", "GET", "HTTP method used for the request")
	urlCmd.Flags().StringSliceP("http-header", "H", []string{}, "HTTP header to pass along with the request (format 'field: value')")
	urlCmd.Flags().StringSlice("fetch-url-pattern", []string{}, "scan URLs in 'application/json' responses matching these paths in the JSON (run 'gitleaks help json' for more info)")
}

var urlCmd = &cobra.Command{
	Use:   "url [flags] url",
	Short: "make HTTP requests and detect secrets in the response",
	Run:   runURL,
}

func runURL(cmd *cobra.Command, args []string) {
	// start timer
	start := time.Now()

	// grab url
	rawURL := ""
	if len(args) == 1 {
		rawURL = args[0]
	}

	if len(rawURL) == 0 {
		logging.Fatal().Err(errors.New("no url provided")).Msg("could not scan URL")
	}

	// setup config (aka, the thing that defines rules)
	initConfig(".")
	initDiagnostics()

	cfg := Config(cmd)

	// create detector
	detector := Detector(cmd, cfg, "")

	// parse flags
	exitCode := mustGetIntFlag(cmd, "exit-code")
	httpMethod := mustGetStringFlag(cmd, "http-method")
	httpHeaderArgs := mustGetStringSliceFlag(cmd, "http-header")
	fetchURLPatterns := mustGetStringSliceFlag(cmd, "fetch-url-pattern")

	findings, err := detector.DetectSource(
		cmd.Context(),
		&sources.URL{
			Config:           &cfg,
			FetchURLPatterns: fetchURLPatterns,
			MaxArchiveDepth:  detector.MaxArchiveDepth,
			HTTPMethod:       httpMethod,
			HTTPHeader:       parseHTTPHeaderArgs(httpHeaderArgs),
			RawURL:           rawURL,
		},
	)

	if err != nil {
		// don't exit on error, just log it
		logging.Error().Err(err).Msg("failed scan URL")
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}

// parseHTTPHeaderArgs converts a {"field: value", ...} list to a http.Header
func parseHTTPHeaderArgs(headerArgs []string) http.Header {
	httpHeader := make(http.Header)

	for _, arg := range headerArgs {
		hv := strings.SplitN(arg, ":", 2)
		if len(hv) != 2 {
			logging.Fatal().Str("invalid_arg", arg).Msg("http-header args must be formatted: 'field: value'")
		}
		header := strings.TrimSpace(hv[0])
		value := strings.TrimSpace(hv[1])
		httpHeader.Add(header, value)
	}

	return httpHeader
}

package cmd

import (
	"errors"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func init() {
	rootCmd.AddCommand(urlCmd)
	urlCmd.Flags().StringP("http-method", "X", "GET", "HTTP method used for the request")
	urlCmd.Flags().StringSliceP("http-header", "H", []string{}, "HTTP header to pass along with the request (format 'Header: value')")
	urlCmd.Flags().StringSlice("fetch-url-pattern", []string{}, "fetch and scan URLs returned in matching JSON response paths (run 'gitleaks help json' for more info)")
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
	httpHeaders := mustGetStringSliceFlag(cmd, "http-header")
	fetchURLPatterns := mustGetStringSliceFlag(cmd, "fetch-url-pattern")

	// convert the 'Header: value' list to a map
	httpHeaderMap := map[string][]string{}
	for _, header := range httpHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 {
			logging.Fatal().Str("invalid_header", header).Msg("headers must be formatted: 'Header: value'")
		}

		header := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])

		if values, ok := httpHeaderMap[header]; ok {
			httpHeaderMap[header] = append(values, value)
		} else {
			httpHeaderMap[header] = []string{value}
		}
	}

	findings, err := detector.DetectSource(
		cmd.Context(),
		&sources.URL{
			Config:           &cfg,
			FetchURLPatterns: fetchURLPatterns,
			MaxArchiveDepth:  detector.MaxArchiveDepth,
			HTTPMethod:       httpMethod,
			HTTPHeaders:      httpHeaderMap,
			RawURL:           rawURL,
		},
	)

	if err != nil {
		// don't exit on error, just log it
		logging.Error().Err(err).Msg("failed scan URL")
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}

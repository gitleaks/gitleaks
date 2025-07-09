package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"
)

const banner = `
    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

`

const configDescription = `config file path
order of precedence:
1. --config/-c
2. env var GITLEAKS_CONFIG
3. env var GITLEAKS_CONFIG_TOML with the file content
4. (target path)/.gitleaks.toml
If none of the four options are used, then gitleaks will use the default config`

var (
	rootCmd = &cobra.Command{
		Use:     "gitleaks",
		Short:   "Gitleaks scans code, past or present, for secrets",
		Version: Version,
	}

	// diagnostics manager is global to ensure it can be started before a scan begins
	// and stopped after a scan completes
	diagnosticsManager *DiagnosticsManager
)

const (
	BYTE     = 1.0
	KILOBYTE = BYTE * 1000
	MEGABYTE = KILOBYTE * 1000
	GIGABYTE = MEGABYTE * 1000
)

func init() {
	cobra.OnInitialize(initLog)
	rootCmd.PersistentFlags().StringP("config", "c", "", configDescription)
	rootCmd.PersistentFlags().Int("exit-code", 1, "exit code when leaks have been encountered")
	rootCmd.PersistentFlags().StringP("report-path", "r", "", "report file")
	rootCmd.PersistentFlags().StringP("report-format", "f", "", "output format (json, csv, junit, sarif, template)")
	rootCmd.PersistentFlags().StringP("report-template", "", "", "template file used to generate the report (implies --report-format=template)")
	rootCmd.PersistentFlags().StringP("baseline-path", "b", "", "path to baseline with issues that can be ignored")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "log level (trace, debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "show verbose output from scan")
	rootCmd.PersistentFlags().BoolP("no-color", "", false, "turn off color for verbose output")
	rootCmd.PersistentFlags().Int("max-target-megabytes", 0, "files larger than this will be skipped")
	rootCmd.PersistentFlags().BoolP("ignore-gitleaks-allow", "", false, "ignore gitleaks:allow comments")
	rootCmd.PersistentFlags().Uint("redact", 0, "redact secrets from logs and stdout. To redact only parts of the secret just apply a percent value from 0..100. For example --redact=20 (default 100%)")
	rootCmd.Flag("redact").NoOptDefVal = "100"
	rootCmd.PersistentFlags().Bool("no-banner", false, "suppress banner")
	rootCmd.PersistentFlags().StringSlice("enable-rule", []string{}, "only enable specific rules by id")
	rootCmd.PersistentFlags().StringP("gitleaks-ignore-path", "i", ".", "path to .gitleaksignore file or folder containing one")
	rootCmd.PersistentFlags().Int("max-decode-depth", 0, "allow recursive decoding up to this depth (default \"0\", no decoding is done)")
	rootCmd.PersistentFlags().Int("max-archive-depth", 0, "allow scanning into nested archives up to this depth (default \"0\", no archive traversal is done)")

	// Add diagnostics flags
	rootCmd.PersistentFlags().String("diagnostics", "", "enable diagnostics (http OR comma-separated list: cpu,mem,trace). cpu=CPU prof, mem=memory prof, trace=exec tracing, http=serve via net/http/pprof")
	rootCmd.PersistentFlags().String("diagnostics-dir", "", "directory to store diagnostics output files when not using http mode (defaults to current directory)")

	err := viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	if err != nil {
		logging.Fatal().Msgf("err binding config %s", err.Error())
	}
}

var logLevel = zerolog.InfoLevel

func initLog() {
	ll, err := rootCmd.Flags().GetString("log-level")
	if err != nil {
		logging.Fatal().Msg(err.Error())
	}

	switch strings.ToLower(ll) {
	case "trace":
		logLevel = zerolog.TraceLevel
	case "debug":
		logLevel = zerolog.DebugLevel
	case "info":
		logLevel = zerolog.InfoLevel
	case "warn":
		logLevel = zerolog.WarnLevel
	case "err", "error":
		logLevel = zerolog.ErrorLevel
	case "fatal":
		logLevel = zerolog.FatalLevel
	default:
		logging.Warn().Msgf("unknown log level: %s", ll)
	}
	logging.Logger = logging.Logger.Level(logLevel)
}

func initConfig(source string) {
	hideBanner, err := rootCmd.Flags().GetBool("no-banner")
	viper.SetConfigType("toml")

	if err != nil {
		logging.Fatal().Msg(err.Error())
	}
	if !hideBanner {
		_, _ = fmt.Fprint(os.Stderr, banner)
	}

	logging.Debug().Msgf("using %s regex engine", regexp.Version)

	cfgPath, err := rootCmd.Flags().GetString("config")
	if err != nil {
		logging.Fatal().Msg(err.Error())
	}
	if cfgPath != "" {
		viper.SetConfigFile(cfgPath)
		logging.Debug().Msgf("using gitleaks config %s from `--config`", cfgPath)
	} else if os.Getenv("GITLEAKS_CONFIG") != "" {
		envPath := os.Getenv("GITLEAKS_CONFIG")
		viper.SetConfigFile(envPath)
		logging.Debug().Msgf("using gitleaks config from GITLEAKS_CONFIG env var: %s", envPath)
	} else if os.Getenv("GITLEAKS_CONFIG_TOML") != "" {
		configContent := []byte(os.Getenv("GITLEAKS_CONFIG_TOML"))
		if err := viper.ReadConfig(bytes.NewBuffer(configContent)); err != nil {
			logging.Fatal().Err(err).Str("content", os.Getenv("GITLEAKS_CONFIG_TOML")).Msg("unable to load gitleaks config from GITLEAKS_CONFIG_TOML env var")
		}
		logging.Debug().Str("content", os.Getenv("GITLEAKS_CONFIG_TOML")).Msg("using gitleaks config from GITLEAKS_CONFIG_TOML env var content")
		return
	} else {
		fileInfo, err := os.Stat(source)
		if err != nil {
			logging.Fatal().Msg(err.Error())
		}

		if !fileInfo.IsDir() {
			logging.Debug().Msgf("unable to load gitleaks config from %s since --source=%s is a file, using default config",
				filepath.Join(source, ".gitleaks.toml"), source)
			if err = viper.ReadConfig(strings.NewReader(config.DefaultConfig)); err != nil {
				logging.Fatal().Msgf("err reading toml %s", err.Error())
			}
			return
		}

		if _, err := os.Stat(filepath.Join(source, ".gitleaks.toml")); os.IsNotExist(err) {
			logging.Debug().Msgf("no gitleaks config found in path %s, using default gitleaks config", filepath.Join(source, ".gitleaks.toml"))

			if err = viper.ReadConfig(strings.NewReader(config.DefaultConfig)); err != nil {
				logging.Fatal().Msgf("err reading default config toml %s", err.Error())
			}
			return
		} else {
			logging.Debug().Msgf("using existing gitleaks config %s from `(--source)/.gitleaks.toml`", filepath.Join(source, ".gitleaks.toml"))
		}

		viper.AddConfigPath(source)
		viper.SetConfigName(".gitleaks")
	}
	if err := viper.ReadInConfig(); err != nil {
		logging.Fatal().Msgf("unable to load gitleaks config, err: %s", err)
	}
}

func initDiagnostics() {
	// Initialize diagnostics manager
	diagnosticsFlag, err := rootCmd.PersistentFlags().GetString("diagnostics")
	if err != nil {
		logging.Fatal().Err(err).Msg("Error getting diagnostics flag")
	}

	diagnosticsDir, err := rootCmd.PersistentFlags().GetString("diagnostics-dir")
	if err != nil {
		logging.Fatal().Err(err).Msg("Error getting diagnostics-dir flag")
	}

	var diagErr error
	diagnosticsManager, diagErr = NewDiagnosticsManager(diagnosticsFlag, diagnosticsDir)
	if diagErr != nil {
		logging.Fatal().Err(diagErr).Msg("Error initializing diagnostics")
	}

	if diagnosticsManager.Enabled {
		logging.Info().Msg("Starting diagnostics...")
		if diagErr := diagnosticsManager.StartDiagnostics(); diagErr != nil {
			logging.Fatal().Err(diagErr).Msg("Failed to start diagnostics")
		}
	}

}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		if strings.Contains(err.Error(), "unknown flag") {
			// exit code 126: Command invoked cannot execute
			os.Exit(126)
		}
		logging.Fatal().Msg(err.Error())
	}
}

func Config(cmd *cobra.Command) config.Config {
	var vc config.ViperConfig
	if err := viper.Unmarshal(&vc); err != nil {
		logging.Fatal().Err(err).Msg("Failed to load config")
	}

	cfg, err := vc.Translate()
	if err != nil {
		logging.Fatal().Err(err).Msg("Failed to load config")
	}
	cfg.Path, _ = cmd.Flags().GetString("config")

	return cfg
}

func Detector(cmd *cobra.Command, cfg config.Config, source string) *detect.Detector {
	var err error

	// Setup common detector
	detector := detect.NewDetector(cfg)

	if detector.MaxDecodeDepth, err = cmd.Flags().GetInt("max-decode-depth"); err != nil {
		logging.Fatal().Err(err).Send()
	}

	if detector.MaxArchiveDepth, err = cmd.Flags().GetInt("max-archive-depth"); err != nil {
		logging.Fatal().Err(err).Send()
	}

	// set color flag at first
	if detector.NoColor, err = cmd.Flags().GetBool("no-color"); err != nil {
		logging.Fatal().Err(err).Send()
	}
	// also init logger again without color
	if detector.NoColor {
		logging.Logger = log.Output(zerolog.ConsoleWriter{
			Out:     os.Stderr,
			NoColor: detector.NoColor,
		}).Level(logLevel)
	}
	detector.Config.Path, err = cmd.Flags().GetString("config")
	if err != nil {
		logging.Fatal().Err(err).Send()
	}

	// if config path is not set, then use the {source}/.gitleaks.toml path.
	// note that there may not be a `{source}/.gitleaks.toml` file, this is ok.
	if detector.Config.Path == "" {
		detector.Config.Path = filepath.Join(source, ".gitleaks.toml")
	}
	// set verbose flag
	if detector.Verbose, err = cmd.Flags().GetBool("verbose"); err != nil {
		logging.Fatal().Err(err).Send()
	}
	// set redact flag
	if detector.Redact, err = cmd.Flags().GetUint("redact"); err != nil {
		logging.Fatal().Err(err).Send()
	}
	if detector.MaxTargetMegaBytes, err = cmd.Flags().GetInt("max-target-megabytes"); err != nil {
		logging.Fatal().Err(err).Send()
	}
	// set ignore gitleaks:allow flag
	if detector.IgnoreGitleaksAllow, err = cmd.Flags().GetBool("ignore-gitleaks-allow"); err != nil {
		logging.Fatal().Err(err).Send()
	}

	gitleaksIgnorePath, err := cmd.Flags().GetString("gitleaks-ignore-path")
	if err != nil {
		logging.Fatal().Err(err).Msg("could not get .gitleaksignore path")
	}

	if fileExists(gitleaksIgnorePath) {
		if err = detector.AddGitleaksIgnore(gitleaksIgnorePath); err != nil {
			logging.Fatal().Err(err).Msg("could not call AddGitleaksIgnore")
		}
	}

	if fileExists(filepath.Join(gitleaksIgnorePath, ".gitleaksignore")) {
		if err = detector.AddGitleaksIgnore(filepath.Join(gitleaksIgnorePath, ".gitleaksignore")); err != nil {
			logging.Fatal().Err(err).Msg("could not call AddGitleaksIgnore")
		}
	}

	if fileExists(filepath.Join(source, ".gitleaksignore")) {
		if err = detector.AddGitleaksIgnore(filepath.Join(source, ".gitleaksignore")); err != nil {
			logging.Fatal().Err(err).Msg("could not call AddGitleaksIgnore")
		}
	}

	// ignore findings from the baseline (an existing report in json format generated earlier)
	baselinePath, _ := cmd.Flags().GetString("baseline-path")
	if baselinePath != "" {
		err = detector.AddBaseline(baselinePath, source)
		if err != nil {
			logging.Error().Msgf("Could not load baseline. The path must point of a gitleaks report generated using the default format: %s", err)
		}
	}

	// If set, only apply rules that are defined in the flag
	rules, _ := cmd.Flags().GetStringSlice("enable-rule")
	if len(rules) > 0 {
		logging.Info().Msg("Overriding enabled rules: " + strings.Join(rules, ", "))
		ruleOverride := make(map[string]config.Rule)
		for _, ruleName := range rules {
			if r, ok := cfg.Rules[ruleName]; ok {
				ruleOverride[ruleName] = r
			} else {
				logging.Fatal().Msgf("Requested rule %s not found in rules", ruleName)
			}
		}
		detector.Config.Rules = ruleOverride
	}

	// Validate report settings.
	reportPath := mustGetStringFlag(cmd, "report-path")
	if reportPath != "" {
		if reportPath != report.StdoutReportPath {
			// Ensure the path is writable.
			if f, err := os.Create(reportPath); err != nil {
				logging.Fatal().Err(err).Msgf("Report path is not writable: %s", reportPath)
			} else {
				_ = f.Close()
				_ = os.Remove(reportPath)
			}
		}

		// Build report writer.
		var (
			reporter       report.Reporter
			reportFormat   = mustGetStringFlag(cmd, "report-format")
			reportTemplate = mustGetStringFlag(cmd, "report-template")
		)
		if reportFormat == "" {
			ext := strings.ToLower(filepath.Ext(reportPath))
			switch ext {
			case ".csv":
				reportFormat = "csv"
			case ".json":
				reportFormat = "json"
			case ".sarif":
				reportFormat = "sarif"
			default:
				logging.Fatal().Msgf("Unknown report format: %s", reportFormat)
			}
			logging.Debug().Msgf("No report format specified, inferred %q from %q", reportFormat, ext)
		}
		switch strings.TrimSpace(strings.ToLower(reportFormat)) {
		case "csv":
			reporter = &report.CsvReporter{}
		case "json":
			reporter = &report.JsonReporter{}
		case "junit":
			reporter = &report.JunitReporter{}
		case "sarif":
			reporter = &report.SarifReporter{
				OrderedRules: cfg.GetOrderedRules(),
			}
		case "template":
			if reporter, err = report.NewTemplateReporter(reportTemplate); err != nil {
				logging.Fatal().Err(err).Msg("Invalid report template")
			}
		default:
			logging.Fatal().Msgf("unknown report format %s", reportFormat)
		}

		// Sanity check.
		if reportTemplate != "" && reportFormat != "template" {
			logging.Fatal().Msgf("Report format must be 'template' if --report-template is specified")
		}

		detector.ReportPath = reportPath
		detector.Reporter = reporter
	}

	return detector
}

func bytesConvert(bytes uint64) string {
	unit := ""
	value := float32(bytes)

	switch {
	case bytes >= GIGABYTE:
		unit = "GB"
		value = value / GIGABYTE
	case bytes >= MEGABYTE:
		unit = "MB"
		value = value / MEGABYTE
	case bytes >= KILOBYTE:
		unit = "KB"
		value = value / KILOBYTE
	case bytes >= BYTE:
		unit = "bytes"
	case bytes == 0:
		return "0"
	}

	stringValue := strings.TrimSuffix(
		fmt.Sprintf("%.2f", value), ".00",
	)

	return fmt.Sprintf("%s %s", stringValue, unit)
}

func findingSummaryAndExit(detector *detect.Detector, findings []report.Finding, exitCode int, start time.Time, err error) {
	if diagnosticsManager.Enabled {
		logging.Debug().Msg("Finalizing diagnostics...")
		diagnosticsManager.StopDiagnostics()
	}

	totalBytes := detector.TotalBytes.Load()
	bytesMsg := fmt.Sprintf("scanned ~%d bytes (%s)", totalBytes, bytesConvert(totalBytes))
	if err == nil {
		logging.Info().Msgf("%s in %s", bytesMsg, FormatDuration(time.Since(start)))
		if len(findings) != 0 {
			logging.Warn().Msgf("leaks found: %d", len(findings))
		} else {
			logging.Info().Msg("no leaks found")
		}
	} else {
		logging.Warn().Msg(bytesMsg)
		logging.Warn().Msgf("partial scan completed in %s", FormatDuration(time.Since(start)))
		if len(findings) != 0 {
			logging.Warn().Msgf("%d leaks found in partial scan", len(findings))
		} else {
			logging.Warn().Msg("no leaks found in partial scan")
		}
	}

	// write report if desired
	if detector.Reporter != nil {
		var (
			file      io.WriteCloser
			reportErr error
		)

		if detector.ReportPath == report.StdoutReportPath {
			file = os.Stdout
		} else {
			// Open the file.
			if file, reportErr = os.Create(detector.ReportPath); reportErr != nil {
				goto ReportEnd
			}
			defer func() {
				_ = file.Close()
			}()
		}

		// Write to the file.
		if reportErr = detector.Reporter.Write(file, findings); reportErr != nil {
			goto ReportEnd
		}

	ReportEnd:
		if reportErr != nil {
			logging.Fatal().Err(reportErr).Msg("failed to write report")
		}
	}

	if err != nil {
		os.Exit(1)
	}

	if len(findings) != 0 {
		os.Exit(exitCode)
	}
}

func fileExists(fileName string) bool {
	// check for a .gitleaksignore file
	info, err := os.Stat(fileName)
	if err != nil && !os.IsNotExist(err) {
		return false
	}

	if info != nil && err == nil {
		if !info.IsDir() {
			return true
		}
	}
	return false
}

func FormatDuration(d time.Duration) string {
	scale := 100 * time.Second
	// look for the max scale that is smaller than d
	for scale > d {
		scale = scale / 10
	}
	return d.Round(scale / 100).String()
}

func mustGetBoolFlag(cmd *cobra.Command, name string) bool {
	value, err := cmd.Flags().GetBool(name)
	if err != nil {
		logging.Fatal().Err(err).Msgf("could not get flag: %s", name)
	}
	return value
}

func mustGetIntFlag(cmd *cobra.Command, name string) int {
	value, err := cmd.Flags().GetInt(name)
	if err != nil {
		logging.Fatal().Err(err).Msgf("could not get flag: %s", name)
	}
	return value
}

func mustGetStringFlag(cmd *cobra.Command, name string) string {
	value, err := cmd.Flags().GetString(name)
	if err != nil {
		logging.Fatal().Err(err).Msgf("could not get flag: %s", name)
	}
	return value
}

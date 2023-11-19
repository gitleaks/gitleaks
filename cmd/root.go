package cmd

import (
	"fmt"
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
3. (--source/-s)/.gitleaks.toml
If none of the three options are used, then gitleaks will use the default config`

var rootCmd = &cobra.Command{
	Use:   "gitleaks",
	Short: "Gitleaks scans code, past or present, for secrets",
}

func init() {
	cobra.OnInitialize(initLog)
	rootCmd.PersistentFlags().StringP("config", "c", "", configDescription)
	rootCmd.PersistentFlags().Int("exit-code", 1, "exit code when leaks have been encountered")
	rootCmd.PersistentFlags().StringP("source", "s", ".", "path to source")
	rootCmd.PersistentFlags().StringP("report-path", "r", "", "report file")
	rootCmd.PersistentFlags().StringP("report-format", "f", "json", "output format (json, csv, junit, sarif)")
	rootCmd.PersistentFlags().StringP("baseline-path", "b", "", "path to baseline with issues that can be ignored")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "log level (trace, debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "show verbose output from scan")
	rootCmd.PersistentFlags().BoolP("no-color", "", false, "turn off color for verbose output")
	rootCmd.PersistentFlags().Int("max-target-megabytes", 0, "files larger than this will be skipped")
	rootCmd.PersistentFlags().BoolP("ignore-gitleaks-allow", "", false, "ignore gitleaks:allow comments")
	rootCmd.PersistentFlags().Uint("redact", 0, "redact secrets from logs and stdout. To redact only parts of the secret just apply a percent value from 0..100. For example --redact=20 (default 100%)")
	rootCmd.Flag("redact").NoOptDefVal = "100"
	rootCmd.PersistentFlags().Bool("no-banner", false, "suppress banner")
	rootCmd.PersistentFlags().String("log-opts", "", "git log options")
	rootCmd.PersistentFlags().StringSlice("enable-rule", []string{}, "only enable specific rules by id, ex: `gitleaks detect --enable-rule=atlassian-api-token --enable-rule=slack-access-token`")
	rootCmd.PersistentFlags().StringP("gitleaks-ignore-path", "i", ".", "path to .gitleaksignore file or folder containing one")
	rootCmd.PersistentFlags().Bool("follow-symlinks", false, "scan files that are symlinks to other files")
	err := viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	if err != nil {
		log.Fatal().Msgf("err binding config %s", err.Error())
	}
}

func initLog() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	ll, err := rootCmd.Flags().GetString("log-level")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	switch strings.ToLower(ll) {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "err", "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

func initConfig() {
	hideBanner, err := rootCmd.Flags().GetBool("no-banner")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	if !hideBanner {
		_, _ = fmt.Fprint(os.Stderr, banner)
	}
	cfgPath, err := rootCmd.Flags().GetString("config")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	if cfgPath != "" {
		viper.SetConfigFile(cfgPath)
		log.Debug().Msgf("using gitleaks config %s from `--config`", cfgPath)
	} else if os.Getenv("GITLEAKS_CONFIG") != "" {
		envPath := os.Getenv("GITLEAKS_CONFIG")
		viper.SetConfigFile(envPath)
		log.Debug().Msgf("using gitleaks config from GITLEAKS_CONFIG env var: %s", envPath)
	} else {
		source, err := rootCmd.Flags().GetString("source")
		if err != nil {
			log.Fatal().Msg(err.Error())
		}
		fileInfo, err := os.Stat(source)
		if err != nil {
			log.Fatal().Msg(err.Error())
		}

		if !fileInfo.IsDir() {
			log.Debug().Msgf("unable to load gitleaks config from %s since --source=%s is a file, using default config",
				filepath.Join(source, ".gitleaks.toml"), source)
			viper.SetConfigType("toml")
			if err = viper.ReadConfig(strings.NewReader(config.DefaultConfig)); err != nil {
				log.Fatal().Msgf("err reading toml %s", err.Error())
			}
			return
		}

		if _, err := os.Stat(filepath.Join(source, ".gitleaks.toml")); os.IsNotExist(err) {
			log.Debug().Msgf("no gitleaks config found in path %s, using default gitleaks config", filepath.Join(source, ".gitleaks.toml"))
			viper.SetConfigType("toml")
			if err = viper.ReadConfig(strings.NewReader(config.DefaultConfig)); err != nil {
				log.Fatal().Msgf("err reading default config toml %s", err.Error())
			}
			return
		} else {
			log.Debug().Msgf("using existing gitleaks config %s from `(--source)/.gitleaks.toml`", filepath.Join(source, ".gitleaks.toml"))
		}

		viper.AddConfigPath(source)
		viper.SetConfigName(".gitleaks")
		viper.SetConfigType("toml")
	}
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal().Msgf("unable to load gitleaks config, err: %s", err)
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		if strings.Contains(err.Error(), "unknown flag") {
			// exit code 126: Command invoked cannot execute
			os.Exit(126)
		}
		log.Fatal().Msg(err.Error())
	}
}

func Config(cmd *cobra.Command) config.Config {
	var vc config.ViperConfig
	if err := viper.Unmarshal(&vc); err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}
	cfg, err := vc.Translate()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}
	cfg.Path, _ = cmd.Flags().GetString("config")

	return cfg
}

func Detector(cmd *cobra.Command, cfg config.Config, source string) *detect.Detector {
	var err error

	// Setup common detector
	detector := detect.NewDetector(cfg)
	// set color flag at first
	if detector.NoColor, err = cmd.Flags().GetBool("no-color"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	// also init logger again without color
	if detector.NoColor {
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:     os.Stderr,
			NoColor: detector.NoColor,
		})
	}
	detector.Config.Path, err = cmd.Flags().GetString("config")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	// if config path is not set, then use the {source}/.gitleaks.toml path.
	// note that there may not be a `{source}/.gitleaks.toml` file, this is ok.
	if detector.Config.Path == "" {
		detector.Config.Path = filepath.Join(source, ".gitleaks.toml")
	}
	// set verbose flag
	if detector.Verbose, err = cmd.Flags().GetBool("verbose"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	// set redact flag
	if detector.Redact, err = cmd.Flags().GetUint("redact"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	if detector.MaxTargetMegaBytes, err = cmd.Flags().GetInt("max-target-megabytes"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	// set ignore gitleaks:allow flag
	if detector.IgnoreGitleaksAllow, err = cmd.Flags().GetBool("ignore-gitleaks-allow"); err != nil {
		log.Fatal().Err(err).Msg("")
	}

	gitleaksIgnorePath, err := cmd.Flags().GetString("gitleaks-ignore-path")
	if err != nil {
		log.Fatal().Err(err).Msg("could not get .gitleaksignore path")
	}

	if fileExists(gitleaksIgnorePath) {
		if err = detector.AddGitleaksIgnore(gitleaksIgnorePath); err != nil {
			log.Fatal().Err(err).Msg("could not call AddGitleaksIgnore")
		}
	}

	if fileExists(filepath.Join(gitleaksIgnorePath, ".gitleaksignore")) {
		if err = detector.AddGitleaksIgnore(filepath.Join(gitleaksIgnorePath, ".gitleaksignore")); err != nil {
			log.Fatal().Err(err).Msg("could not call AddGitleaksIgnore")
		}
	}

	if fileExists(filepath.Join(source, ".gitleaksignore")) {
		if err = detector.AddGitleaksIgnore(filepath.Join(source, ".gitleaksignore")); err != nil {
			log.Fatal().Err(err).Msg("could not call AddGitleaksIgnore")
		}
	}

	// ignore findings from the baseline (an existing report in json format generated earlier)
	baselinePath, _ := cmd.Flags().GetString("baseline-path")
	if baselinePath != "" {
		err = detector.AddBaseline(baselinePath, source)
		if err != nil {
			log.Error().Msgf("Could not load baseline. The path must point of a gitleaks report generated using the default format: %s", err)
		}
	}

	// If set, only apply rules that are defined in the flag
	rules, _ := cmd.Flags().GetStringSlice("enable-rule")
	if len(rules) > 0 {
		log.Info().Msg("Overriding enabled rules: " + strings.Join(rules, ", "))
		ruleOverride := make(map[string]config.Rule)
		for _, ruleName := range rules {
			if rule, ok := cfg.Rules[ruleName]; ok {
				ruleOverride[ruleName] = rule
			} else {
				log.Fatal().Msgf("Requested rule %s not found in rules", ruleName)
			}
		}
		detector.Config.Rules = ruleOverride
	}

	// set follow symlinks flag
	if detector.FollowSymlinks, err = cmd.Flags().GetBool("follow-symlinks"); err != nil {
		log.Fatal().Err(err).Msg("")
	}
	return detector
}

func findingSummaryAndExit(findings []report.Finding, cmd *cobra.Command, cfg config.Config, exitCode int, start time.Time, err error) {
	if err == nil {
		log.Info().Msgf("scan completed in %s", FormatDuration(time.Since(start)))
		if len(findings) != 0 {
			log.Warn().Msgf("leaks found: %d", len(findings))
		} else {
			log.Info().Msg("no leaks found")
		}
	} else {
		log.Warn().Msgf("partial scan completed in %s", FormatDuration(time.Since(start)))
		if len(findings) != 0 {
			log.Warn().Msgf("%d leaks found in partial scan", len(findings))
		} else {
			log.Warn().Msg("no leaks found in partial scan")
		}
	}

	// write report if desired
	reportPath, _ := cmd.Flags().GetString("report-path")
	ext, _ := cmd.Flags().GetString("report-format")
	if reportPath != "" {
		if err := report.Write(findings, cfg, ext, reportPath); err != nil {
			log.Fatal().Err(err).Msg("could not write")
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

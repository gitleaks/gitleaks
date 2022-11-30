package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/config"
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
	rootCmd.PersistentFlags().StringP("source", "s", ".", "path to source (default: $PWD)")
	rootCmd.PersistentFlags().StringP("report-path", "r", "", "report file")
	rootCmd.PersistentFlags().StringP("report-format", "f", "json", "output format (json, csv, junit, sarif)")
	rootCmd.PersistentFlags().StringP("baseline-path", "b", "", "path to baseline with issues that can be ignored")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "log level (trace, debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "show verbose output from scan")
	rootCmd.PersistentFlags().Int("max-target-megabytes", 0, "files larger than this will be skipped")
	rootCmd.PersistentFlags().Bool("redact", false, "redact secrets from logs and stdout")
	rootCmd.PersistentFlags().Bool("no-banner", false, "suppress banner")
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

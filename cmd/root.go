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
2. (--source/-s)/.gitleaks.toml
if --config/-c is not set and no (--source/s)/.gitleaks.toml is present 
then .gitleaks.toml will be written to (--source/-s)/.gitleaks.toml for future use`

var rootCmd = &cobra.Command{
	Use:   "gitleaks",
	Short: "Gitleaks scans code, past or present, for secrets",
}

func init() {
	cobra.OnInitialize(initLog)
	rootCmd.PersistentFlags().StringP("config", "c", "", configDescription)
	rootCmd.PersistentFlags().Int("exit-code", 1, "exit code when leaks have been encountered (default: 1)")
	rootCmd.PersistentFlags().StringP("source", "s", ".", "path to source (default: $PWD)")
	rootCmd.PersistentFlags().StringP("report-path", "r", "", "report file")
	rootCmd.PersistentFlags().StringP("report-format", "f", "", "output format (json, csv, sarif)")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "log level (debug, info, warn, error, fatal)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "show verbose output from scan")
	rootCmd.PersistentFlags().Bool("redact", false, "redact secrets from logs and stdout")
	viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
}

func initLog() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	ll, err := rootCmd.Flags().GetString("log-level")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	switch strings.ToLower(ll) {
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
	fmt.Fprintf(os.Stderr, banner)
	cfgPath, err := rootCmd.Flags().GetString("config")
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	if cfgPath != "" {
		viper.SetConfigFile(cfgPath)
		log.Debug().Msgf("Using gitleaks config %s", cfgPath)
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
			log.Debug().Msgf("Unable to write default gitleaks config to %s since --source=%s is a file, using default config",
				filepath.Join(source, ".gitleaks.toml"), source)
			viper.SetConfigType("toml")
			viper.ReadConfig(strings.NewReader(config.DefaultConfig))
			return
		}

		if _, err := os.Stat(filepath.Join(source, ".gitleaks.toml")); os.IsNotExist(err) {
			log.Debug().Msgf("No gitleaks config found, writing default gitleaks config to %s", filepath.Join(source, ".gitleaks.toml"))
			if err := os.WriteFile(filepath.Join(source, ".gitleaks.toml"), []byte(config.DefaultConfig), os.ModePerm); err != nil {
				log.Debug().Msgf("Unable to write default gitleaks config to %s, using default config", filepath.Join(source, ".gitleaks.toml"))
				viper.SetConfigType("toml")
				viper.ReadConfig(strings.NewReader(config.DefaultConfig))
				return
			}
		} else {
			log.Debug().Msgf("Using existing gitleaks config %s", filepath.Join(source, ".gitleaks.toml"))
		}

		viper.AddConfigPath(source)
		viper.SetConfigName(".gitleaks")
		viper.SetConfigType("toml")
	}
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal().Msgf("Unable to load gitleaks config, err: %s", err)
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

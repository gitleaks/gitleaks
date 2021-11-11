package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zricethezav/gitleaks/v8/config"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const banner = `
    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks 

`

var rootCmd = &cobra.Command{
	Use:   "gitleaks",
	Short: "Gitleaks scans code, past or present, for secrets",
}

var cfgFile string

func init() {
	// On init we will read a gitleaks configuration file if one exists.
	// The default path for a gitleaks config is `$HOME/.config/gitleaks/gitleaks.toml.
	// If that file does not exist gitleaks will save the default configuration file to that
	// location.
	cobra.OnInitialize(initConfig)
	cobra.OnInitialize(initLog)
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is $HOME/.config/gitleaks/gitleaks.toml)")
	rootCmd.PersistentFlags().String("exit-code", "", "exit code when leaks have been encountered (default: 1)")
	rootCmd.PersistentFlags().StringP("source", "s", "", "path to source")
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
		log.Fatal().Err(err)
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
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := homedir.Dir()
		if err != nil {
			log.Fatal().Err(err)
		}
		cfgPath := filepath.Join(home, ".config", "gitleaks")
		if _, err := os.Stat(filepath.Join(cfgPath, "gitleaks.toml")); os.IsNotExist(err) {
			// no config found, write default config to $HOME/.config/gitleaks/gitleaks.toml
			log.Debug().Msgf("No gitleaks config found, writing default gitleaks config to %s\n", filepath.Join(cfgPath, "gitleaks.toml"))
			if err := os.MkdirAll(cfgPath, os.ModePerm); err != nil {
				log.Debug().Msgf("Unable to write default gitleaks config to %s\n", filepath.Join(cfgPath, "gitleaks.toml"))
			}
			if err := os.WriteFile(filepath.Join(cfgPath, "gitleaks.toml"), []byte(config.DefaultConfig), os.ModePerm); err != nil {
				log.Debug().Msgf("Unable to write default gitleaks config to %s\n", filepath.Join(cfgPath, "gitleaks.toml"))
			}
		}

		viper.AddConfigPath(cfgPath)
		viper.SetConfigName("gitleaks")
		viper.SetConfigType("toml")
	}
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal().Msgf("Unable to load gitleaks config, err: %s", err)
	}
}

func Execute() {
	fmt.Fprintf(os.Stderr, banner)
	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err)
	}
}

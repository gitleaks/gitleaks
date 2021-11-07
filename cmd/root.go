package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/zricethezav/gitleaks/v8/config"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const banner = `
    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks %s 

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
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is $HOME/.config/gitleaks/gitleaks.toml)")
	rootCmd.PersistentFlags().String("exit-code", "", "exit code when leaks have been encountered (default: 1)")
	rootCmd.PersistentFlags().StringP("source", "s", "", "path to source")
	rootCmd.PersistentFlags().StringP("report-path", "r", "", "report file")
	rootCmd.PersistentFlags().StringP("report-format", "f", "", "output format (json, csv, sarif)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "show verbose output from scan")
	rootCmd.PersistentFlags().Bool("redact", false, "redact secrets from logs and stdout")
	viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		cfgPath := filepath.Join(home, ".config", "gitleaks")
		if _, err := os.Stat(filepath.Join(cfgPath, "gitleaks.toml")); os.IsNotExist(err) {
			// no config found, write default config to $HOME/.config/gitleaks/gitleaks.toml
			fmt.Printf("No gitleaks config found, writing default gitleaks config to %s\n", filepath.Join(cfgPath, "gitleaks.toml"))
			if err := os.MkdirAll(cfgPath, os.ModePerm); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			if err := os.WriteFile(filepath.Join(cfgPath, "gitleaks.toml"), []byte(config.DefaultConfig), os.ModePerm); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}

		viper.AddConfigPath(cfgPath)
		viper.SetConfigName("gitleaks")
		viper.SetConfigType("toml")

	}
	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Can't read config:", err)
		os.Exit(1)
	}
}

func Execute() {
	fmt.Fprintf(os.Stderr, banner, Version)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

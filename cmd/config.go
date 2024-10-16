package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/manage"
	"os"
	"path/filepath"
)

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configFetchCmd)
	configFetchCmd.Flags().StringP("url", "u", "", "URL of remote configuration file.")
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "manage custom Gitleaks config",
}

var configFetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "fetch custom config from a remote URL. Config will be written to ~/.config/gitleaks/config.toml",
	Run:   runFetch,
}

func runFetch(cmd *cobra.Command, args []string) {
	// check if URL flag is set
	rawURL, err := cmd.Flags().GetString("url")
	if err != nil || rawURL == "" {
		log.Fatal().Err(err).Msg("unable to get URL flag")
	}

	// build file path
	homeDir, err := os.UserHomeDir()
	targetPath := filepath.Join(homeDir, gitleaksHomeConfigRelPath)

	// Setup config handler
	m := manage.NewConfigManager()

	// fetch config and write to target
	err = m.FetchTo(rawURL, targetPath)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to fetch config")
	}

	log.Info().Msgf("config written to %s", targetPath)
}

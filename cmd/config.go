package cmd

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/config"
	"path/filepath"
)

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configFetchCmd)
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "manage custom Gitleaks config",
}

var configFetchCmd = &cobra.Command{
	Use:   "fetch [url]",
	Short: "fetch custom config from a remote URL",
	Long:  "fetch custom config from a remote URL. Config will be written to ~/.config/gitleaks/config.toml",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runFetch(cmd, args, localConfigPaths)
	},
}

func runFetch(cmd *cobra.Command, args []string, localConfigPaths LocalConfigPaths) {
	// check if URL flag is set
	rawURL := args[0]

	// build file path
	targetPath := filepath.Join(localConfigPaths.ConfigDir, localConfigPaths.GitleaksFile)

	// Setup config handler
	remoteConfig := config.NewRemoteConfig()
	if err := remoteConfig.WriteTo(rawURL, targetPath); err != nil {
		log.Fatal().Err(err).Msg("unable to fetch remote config")
	}

	log.Info().Msgf("config written to %s", targetPath)
}

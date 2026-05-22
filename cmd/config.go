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
	configCmd.AddCommand(configResetCmd)
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

var configResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "removes the fetched config file",
	Long:  "removes the fetched config file from ${XDG_CONFIG_HOME}/gitleaks/config.toml, ensuring gitleaks reverts back to the default ruleset",
	Run: func(cmd *cobra.Command, args []string) {
		runReset(cmd, args, localConfigPaths)
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

func runReset(cmd *cobra.Command, args []string, localConfigPaths LocalConfigPaths) {
	targetPath := filepath.Join(localConfigPaths.ConfigDir, localConfigPaths.GitleaksFile)

	remoteConfig := config.NewRemoteConfig()

	status, err := remoteConfig.Reset(targetPath)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to reset config")
		return
	}

	switch status {
	case config.FileNotFound:
		log.Info().Msgf("No config file at %s found", targetPath)
	case config.FileRemoved:
		log.Info().Msgf("Config file at %s removed", targetPath)
	default:
		log.Warn().Msgf("Unexpected status: %d", status)
	}

}

package cmd

import (
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"io"
	"net/http"
	url "net/url"
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

	homeDir, err := os.UserHomeDir()

	filePath := filepath.Join(homeDir, ".config", "gitleaks", "config.toml")

	var resp []byte
	if isValidURL(rawURL) {
		resp, err = downloadConfig(rawURL)
		if err != nil {
			log.Fatal().Err(err).Msg("could not download config from remote url")
		}
	} else {
		log.Fatal().Msg("invalid URL url")
	}

	dirPath := filepath.Dir(filePath)
	if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
		panic(fmt.Errorf("failed to create directory: %v", err))
	}

	file, err := os.Create(filePath)
	if err != nil {
		panic(fmt.Errorf("failed to create or open file: %w", err))
	}
	defer file.Close()

	_, err = file.Write(resp)
	if err != nil {
		panic(fmt.Errorf("failed to write to file: %w", err))
	}

	log.Info().Msgf("config written to %s", filePath)
}

func isValidURL(rawURL string) bool {
	_, err := url.ParseRequestURI(rawURL)
	return err == nil
}

func downloadConfig(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download config from URL: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	return body, nil
}

package cmd

import (
	"bufio"
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

func isValidURL(rawURL string) bool {
	_, err := url.ParseRequestURI(rawURL)
	return err == nil
}

func fetchConfig(url string) ([]byte, error) {
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

func writeToDisk(content []byte, filePath string) (int, error) {
	// create directory path if not already created
	dirPath := filepath.Dir(filePath)
	if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
		return 0, fmt.Errorf("failed to create directory ~/.config/gitleaks : %v", err)
	}

	// Create a temporary file in the same directory
	tempFile, err := os.CreateTemp(dirPath, "gitleaks-config-*.tmp")
	if err != nil {
		return 0, fmt.Errorf("failed to create temporary file: %v", err)
	}
	tempFilePath := tempFile.Name()
	defer os.Remove(tempFilePath) // Clean up the temp file in case of failure

	// Write to the temporary file
	writer := bufio.NewWriter(tempFile)
	bytesWritten, err := writer.Write(content)
	if err != nil {
		return 0, fmt.Errorf("failed to write to temporary file: %v", err)
	}

	// flush changes to disk
	if err = writer.Flush(); err != nil {
		return 0, fmt.Errorf("failed to flush writer: %v", err)
	}

	if err = tempFile.Close(); err != nil {
		return 0, fmt.Errorf("failed to close temporary file: %v", err)
	}

	// replaces or creates the expected file
	if err = os.Rename(tempFilePath, filePath); err != nil {
		return 0, fmt.Errorf("failed to rename temporary file: %v", err)
	}

	return bytesWritten, nil
}

func runFetch(cmd *cobra.Command, args []string) {
	// check if URL flag is set
	rawURL, err := cmd.Flags().GetString("url")
	if err != nil || rawURL == "" {
		log.Fatal().Err(err).Msg("unable to get URL flag")
	}

	// build file path
	homeDir, err := os.UserHomeDir()
	filePath := filepath.Join(homeDir, gitleaksHomeConfigRelPath)

	// check if URL is valid and download config
	var resp []byte
	if isValidURL(rawURL) {
		resp, err = fetchConfig(rawURL)
		if err != nil {
			log.Fatal().Err(err).Msg("could not download config from remote url")
		}
	} else {
		log.Fatal().Msg("invalid URL url")
	}

	// write downloaded config to ~/.config/gitleaks/config.toml
	_, err = writeToDisk(resp, filePath)
	if err != nil {
		panic(fmt.Errorf("failed to write config to disk : %v", err))
	}

	log.Info().Msgf("config written to %s", filePath)
}

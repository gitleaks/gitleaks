package manage

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

type ConfigManager struct{}

func NewConfigManager() *ConfigManager {
	return &ConfigManager{}
}

func (c *ConfigManager) FetchTo(rawURL, targetPath string) error {
	var (
		resp []byte
		err  error
	)

	resp, err = c.fetch(rawURL)
	if err != nil {
		return fmt.Errorf("could not download config from remote url: %w", err)
	}

	// write downloaded config to ~/.config/gitleaks/config.toml
	_, err = c.writeToDisk(resp, targetPath)
	if err != nil {
		return fmt.Errorf("failed to write config to disk : %v", err)
	}

	return nil
}

func isValidURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Check if the scheme is HTTP or HTTPS
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	// Check if the host is present
	if u.Host == "" {
		return false
	}

	return true
}

func (c *ConfigManager) fetch(rawURL string) ([]byte, error) {
	if !isValidURL(rawURL) {
		return nil, fmt.Errorf("invalid URL")
	}

	resp, err := http.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download config from URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status code:%d returned from remote URL", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("empty response body from URL")
	}

	return body, nil
}

func (c *ConfigManager) writeToDisk(content []byte, filePath string) (int, error) {
	// create directory path if not already created
	dirPath := filepath.Dir(filePath)
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return 0, fmt.Errorf("failed to create directory ~/.config/gitleaks : %v", err)
	}

	// Create a temporary file in the same directory
	tempFile, err := os.CreateTemp(dirPath, "gitleaks-config-*.tmp")
	if err != nil {
		return 0, fmt.Errorf("failed to create temporary file: %v", err)
	}
	tempFilePath := tempFile.Name()
	defer func() {
		if removeErr := os.Remove(tempFilePath); removeErr != nil {
			err = fmt.Errorf("failed to remove temporary file: %v (original error: %v)", removeErr, err)
		} // Clean up the temp file in case of failure
	}()

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

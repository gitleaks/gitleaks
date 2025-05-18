package config

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	m "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type RemoteConfig struct{}

type FileRemovalStatus int

const (
	FileNotFound FileRemovalStatus = iota
	FileRemoved
	FileIsDirectory
	PermissionDenied
	UnknownError
)

func NewRemoteConfig() *RemoteConfig {
	return &RemoteConfig{}
}

func (c *RemoteConfig) WriteTo(rawURL, targetPath string) error {
	var (
		resp []byte
		err  error
	)

	resp, err = retry(context.Background(), 3, func(ctx context.Context) ([]byte, error) {
		return c.fetch(rawURL)
	})

	if err != nil {
		return fmt.Errorf("failed to download config from remote url: %w", err)
	}

	// write downloaded config to target path
	_, err = writeToDisk(resp, targetPath)
	if err != nil {
		return fmt.Errorf("failed to write config to disk : %w", err)
	}

	return nil
}

func (c *RemoteConfig) fetch(rawURL string) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download config from URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status code:%d returned from remote URL", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("empty response body from URL")
	}

	return body, nil
}

func (c *RemoteConfig) Reset(targetPath string) (FileRemovalStatus, error) {
	fileInfo, err := os.Lstat(targetPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return FileNotFound, nil
		} else if errors.Is(err, os.ErrPermission) {
			return PermissionDenied, fmt.Errorf("permission denied: %w", err)
		}
		return UnknownError, fmt.Errorf("failed to stat file: %w", err)
	}

	if fileInfo.IsDir() {
		return FileIsDirectory, fmt.Errorf("cannot remove directory: %w", err)
	}

	if err := os.Remove(targetPath); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return PermissionDenied, fmt.Errorf("permission denied: cannot remove %w", err)
		}
		return UnknownError, fmt.Errorf("error removing file: %w", err)
	}

	return FileRemoved, nil
}

func retry[T any](ctx context.Context, maxAttempts int, fn func(ctx context.Context) (T, error)) (T, error) {
	var result T
	var err error

	initialDelay := 1 * time.Second
	maxDelay := 30 * time.Second // Added maxDelay

	for attempt := 0; attempt < maxAttempts; attempt++ {
		result, err = fn(ctx)

		if err == nil {
			return result, nil
		}

		// Calculate exponential backoff with jitter.
		delay := initialDelay * time.Duration(math.Pow(2, float64(attempt)))
		// Add some jitter (using crypto/rand for security).
		jitter, randErr := rand.Int(rand.Reader, big.NewInt(int64(delay/4)))
		if randErr != nil {
			// Fallback to a less secure random number if crypto/rand fails.
			jitter = big.NewInt(m.Int63n(int64(delay / 4)))
		}
		delay += time.Duration(jitter.Int64())

		if delay > maxDelay {
			delay = maxDelay
		}

		select {
		case <-time.After(delay): // Wait for the delay.
		case <-ctx.Done(): // Check for context cancellation.
			return result, ctx.Err() // Return context error if cancelled.
		}
	}

	return result, fmt.Errorf("failed after %d attempts: %w", maxAttempts, err) // Wrap the final error.
}

func writeToDisk(content []byte, filePath string) (int, error) {
	// create directory path if not already created
	dirPath := filepath.Dir(filePath)
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return 0, fmt.Errorf("failed to create directory ~/.config/gitleaks : %w", err)
	}

	// Create a temporary file in the same directory
	tempFile, err := os.CreateTemp(dirPath, "gitleaks-config-*.tmp")
	if err != nil {
		return 0, fmt.Errorf("failed to create temporary file: %w", err)
	}
	tempFilePath := tempFile.Name()
	defer func() {
		if removeErr := os.Remove(tempFilePath); removeErr != nil {
			err = fmt.Errorf("failed to remove temporary file: %w (original error: %w)", removeErr, err)
		} // Clean up the temp file in case of failure
	}()

	// Write to the temporary file
	writer := bufio.NewWriter(tempFile)
	bytesWritten, err := writer.Write(content)
	if err != nil {
		return 0, fmt.Errorf("failed to write to temporary file: %w", err)
	}

	// flush changes to disk
	if err = writer.Flush(); err != nil {
		return 0, fmt.Errorf("failed to flush writer: %w", err)
	}

	if err = tempFile.Close(); err != nil {
		return 0, fmt.Errorf("failed to close temporary file: %w", err)
	}

	// replaces or creates the expected file
	if err = os.Rename(tempFilePath, filePath); err != nil {
		return 0, fmt.Errorf("failed to rename temporary file: %w", err)
	}

	return bytesWritten, nil
}

package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

type URL struct {
	Config           *config.Config
	FetchURLPatterns []string
	HTTPClient       *http.Client
	MaxArchiveDepth  int
	RawURL           string
}

func (s *URL) Fragments(ctx context.Context, yield FragmentsFunc) error {
	parsedURL, err := url.Parse(s.RawURL)
	if err != nil {
		return fmt.Errorf("could not parse URL: %w", err)
	}

	if s.HTTPClient == nil {
		s.HTTPClient = NewHTTPClient()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", s.RawURL, nil)
	if err != nil {
		return fmt.Errorf("error creating HTTP GET request: %w", err)
	}

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP GET error: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: status_code=%d", resp.StatusCode)
	}

	defer (func() {
		if err := resp.Body.Close(); err != nil {
			logging.Debug().Err(err).Str("url", s.RawURL).Msg("error closing url source response body: %v url=%q")
		}
	})()

	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("could not read JSON response body: %w", err)
		}

		json := &JSON{
			Config:           s.Config,
			FetchURLPatterns: s.FetchURLPatterns,
			HTTPClient:       s.HTTPClient,
			MaxArchiveDepth:  s.MaxArchiveDepth,
			Path:             parsedURL.Path,
			RawMessage:       data,
		}

		return json.Fragments(ctx, yield)
	}

	file := &File{
		Config:          s.Config,
		Content:         resp.Body,
		MaxArchiveDepth: s.MaxArchiveDepth,
		Path:            parsedURL.Path,
	}

	return file.Fragments(ctx, yield)
}

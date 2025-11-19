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
	HTTPHeader       http.Header
	HTTPMethod       string
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

	method := "GET"
	if len(s.HTTPMethod) > 0 {
		method = s.HTTPMethod
	}

	req, err := http.NewRequestWithContext(ctx, method, s.RawURL, nil)
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %w", err)
	}

	req.Header = s.HTTPHeader
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP error: %w", err)
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
		jsonText, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("could not read JSON response body: %w", err)
		}

		json := &JSON{
			Config:           s.Config,
			FetchURLPatterns: s.FetchURLPatterns,
			HTTPClient:       s.HTTPClient,
			HTTPHeader:       s.HTTPHeader,
			MaxArchiveDepth:  s.MaxArchiveDepth,
			Path:             parsedURL.Path,
			Text:             jsonText,
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

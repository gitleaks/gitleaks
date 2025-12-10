package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

var urlRegexp = regexp.MustCompile(`^https?:\/\/\S+$`)

// JSON is a source for yielding fragments from strings in a json text
// and from URLs contained in the data that match FetchURLGlobs
type JSON struct {
	Config          *config.Config
	FetchURLGlobs   []string
	HTTPClient      *http.Client
	HTTPHeader      http.Header
	MaxArchiveDepth int
	Path            string
	Text            json.RawMessage
	data            any
}

type jsonNode struct {
	path  string
	value any
}

// Fragments yields the fragments contained in this resource
func (s *JSON) Fragments(ctx context.Context, yield FragmentsFunc) error {
	if s.data == nil {
		if err := json.Unmarshal([]byte(s.Text), &s.data); err != nil {
			return fmt.Errorf("could not unmarshal json text: %w", err)
		}
	}

	return s.walkAndYield(ctx, jsonNode{path: s.Path, value: s.data}, yield)
}

func (s *JSON) walkAndYield(ctx context.Context, currentNode jsonNode, yield FragmentsFunc) error {
	switch obj := currentNode.value.(type) {
	case map[string]any:
		for key, value := range obj {
			childNode := jsonNode{
				path:  s.joinPath(currentNode.path, key),
				value: value,
			}
			if err := s.walkAndYield(ctx, childNode, yield); err != nil {
				return err
			}
		}

		return nil
	case []any:
		for i, value := range obj {
			childNode := jsonNode{
				path:  s.joinPath(currentNode.path, strconv.Itoa(i)),
				value: value,
			}
			if err := s.walkAndYield(ctx, childNode, yield); err != nil {
				return err
			}
		}

		return nil
	case string:
		if s.shouldFetchURL(currentNode.path) && urlRegexp.MatchString(obj) {
			logging.Info().Str("path", currentNode.path).Str("method", "GET").Str("url", obj).Msg("fetching URL")

			if s.HTTPClient == nil {
				s.HTTPClient = NewHTTPClient()
			}

			req, err := http.NewRequestWithContext(ctx, "GET", obj, nil)
			if err != nil {
				logging.Error().Err(err).Str("path", currentNode.path).Msg("json fetch url failed")
				return nil
			}

			req.Header = s.HTTPHeader
			resp, err := s.HTTPClient.Do(req)
			if err != nil {
				logging.Error().Err(err).Str("path", currentNode.path).Msg("json fetch url failed")
				return nil
			}

			if resp.StatusCode != http.StatusOK {
				logging.Error().Int("status_code", resp.StatusCode).Str("path", currentNode.path).Msg("json fetch url failed with an unexpected status code")
				logging.Trace().Str("path", currentNode.path).Msg("converting response to a file source")
				file := &File{
					Config:          s.Config,
					Content:         strings.NewReader(obj),
					MaxArchiveDepth: s.MaxArchiveDepth,
					Path:            currentNode.path,
				}

				return file.Fragments(ctx, yield)
			}

			defer (func() {
				if err := resp.Body.Close(); err != nil {
					logging.Debug().Err(err).Msg("error closing json source response body")
				}
			})()

			// Handle when the URL returns more json
			if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
				jsonText, err := io.ReadAll(resp.Body)
				if err != nil {
					logging.Error().Err(err).Str("path", currentNode.path).Msg("could not read fetched json response body")
					return nil
				}

				logging.Trace().Str("path", currentNode.path).Msg("converting response to a JSON source")
				jsonSource := &JSON{
					Config:          s.Config,
					HTTPClient:      s.HTTPClient,
					MaxArchiveDepth: s.MaxArchiveDepth,
					Path:            currentNode.path,
					Text:            jsonText,
				}

				return jsonSource.Fragments(ctx, yield)
			}

			logging.Trace().Str("path", currentNode.path).Msg("converting value to a file source")
			file := &File{
				Content:         resp.Body,
				MaxArchiveDepth: s.MaxArchiveDepth,
				Path:            currentNode.path,
			}

			return file.Fragments(ctx, yield)
		}

		logging.Trace().Str("path", currentNode.path).Msg("converting value to a file source")
		file := &File{
			Content:         strings.NewReader(obj),
			MaxArchiveDepth: s.MaxArchiveDepth,
			Path:            currentNode.path,
		}

		return file.Fragments(ctx, yield)
	default:
		return nil
	}
}

func (s *JSON) joinPath(root, child string) string {
	switch root {
	case "":
		return child
	case s.Path:
		return root + InnerPathSeparator + child
	default:
		return filepath.Clean(root + "/" + child)
	}
}

func (s *JSON) shouldFetchURL(path string) bool {
	if len(s.FetchURLGlobs) == 0 {
		return false
	}

	for _, glob := range s.FetchURLGlobs {
		if pathGlobMatch(glob, path) {
			return true
		}
	}

	return false
}

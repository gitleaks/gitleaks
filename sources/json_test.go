package sources

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSON(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		var content string

		assert.Equal(t, "GET", r.Method)

		switch r.URL.Path {
		case "/hello":
			content = "hello world"
		case "/hello.json":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			content = `{"hello": "world"}`
		case "/leak.json":
			w.Header().Add("Content-Type", "application/json")
			content = `{"quay.io": {"auth": "SUPER SECRET"}}`
		default:
			content = "Not sure what happened here"
		}

		w.WriteHeader(http.StatusOK)
		_, err = io.WriteString(w, content)

		assert.NoError(t, err)
	}))

	ts.Start()
	defer ts.Close()

	data := `{
			"foo": "bar",
			"baz": ["bop", true, 1, 2.3, null, {"hello": "there"}],
			"url": "` + ts.URL + `/hello",
			"nested": {"url": "` + ts.URL + `/hello.json"},
			"skipped": "https://example.com",
			"invalid": "https://raw.githubusercontent.com/leaktk/fake-leaks/main/this-url-doesnt-exist-8UaehX5b24MzZiaeJ428FK5R",
			"jsonurl":  "` + ts.URL + `/leak.json"
	}`

	jsonData := &JSON{
		RawMessage:       json.RawMessage(data),
		FetchURLPatterns: []string{"url", "nested/*", "invalid", "jsonurl"},
	}

	fragments := []Fragment{}
	err := jsonData.Fragments(context.Background(), func(fragment Fragment, err error) error {
		fragments = append(fragments, fragment)

		return nil
	})

	require.NoError(t, err)
	expected := map[string]string{
		"foo":         "bar",
		"baz/0":       "bop",
		"baz/5/hello": "there",
		"url":         "hello world",
		"nested/url" + InnerPathSeparator + "hello": "world",
		"skipped": "https://example.com",
		"invalid": "https://raw.githubusercontent.com/leaktk/fake-leaks/main/this-url-doesnt-exist-8UaehX5b24MzZiaeJ428FK5R",
		"jsonurl" + InnerPathSeparator + "quay.io/auth": "SUPER SECRET",
	}

	assert.Len(t, fragments, 8)

	for _, fragment := range fragments {
		assert.Contains(t, expected, fragment.FilePath)
		assert.Equal(t, expected[fragment.FilePath], fragment.Raw, "path=%s", fragment.FilePath)
	}
}

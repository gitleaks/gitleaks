package sources

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURL(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var content string

		switch r.URL.Path {
		case "/general":
			w.Header().Add("Content-Type", "text/plain")
			content = "general-content"
		case "/data.json":
			w.Header().Add("Content-Type", "application/json")
			content = "{\"data\": \"json-data\"}"
		default:
			t.Errorf("invalid URL path: path=%q", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		_, err := io.WriteString(w, content)
		assert.NoError(t, err)
	}))

	ts.Start()
	defer ts.Close()

	// Test general content
	generalURL, err := url.JoinPath(ts.URL, "general")
	require.NoError(t, err)

	source := URL{
		RawURL: generalURL,
	}

	fragments := []Fragment{}
	err = source.Fragments(context.Background(), func(fragment Fragment, err error) error {
		fragments = append(fragments, fragment)

		return nil
	})

	require.NoError(t, err)
	assert.Len(t, fragments, 1)
	assert.Equal(t, "/general", fragments[0].FilePath)
	assert.Equal(t, "general-content", fragments[0].Raw)

	// Test json data
	jsonDataURL, err := url.JoinPath(ts.URL, "data.json")
	require.NoError(t, err)
	source = URL{
		RawURL: jsonDataURL,
	}

	fragments = []Fragment{}
	err = source.Fragments(context.Background(), func(fragment Fragment, err error) error {
		fragments = append(fragments, fragment)

		return nil
	})

	require.NoError(t, err)
	assert.Len(t, fragments, 1)
	assert.Equal(t, "/data.json!data", fragments[0].FilePath)
	assert.Equal(t, "json-data", fragments[0].Raw)
}

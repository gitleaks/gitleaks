package detect

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecode(t *testing.T) {
	tests := []struct {
		chunk    string
		expected string
		name     string
	}{
		{
			name:     "only b64 chunk",
			chunk:    `bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`,
			expected: `longer-encoded-secret-test`,
		},
		{
			name:     "mixed content",
			chunk:    `token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`,
			expected: `token: longer-encoded-secret-test`,
		},
		{
			name:     "no chunk",
			chunk:    ``,
			expected: ``,
		},
		{
			name:     "env var (looks like all b64 decodable but has `=` in the middle)",
			chunk:    `some-encoded-secret=dGVzdC1zZWNyZXQtdmFsdWU=`,
			expected: `some-encoded-secret=test-secret-value`,
		},
		{
			name:     "has longer b64 inside",
			chunk:    `some-encoded-secret="bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q="`,
			expected: `some-encoded-secret="longer-encoded-secret-test"`,
		},
		{
			name: "many possible i := 0substrings",
			chunk: `Many substrings in this slack message could be base64 decoded
				but only dGhpcyBlbmNhcHN1bGF0ZWQgc2VjcmV0 should be decoded.`,
			expected: `Many substrings in this slack message could be base64 decoded
				but only this encapsulated secret should be decoded.`,
		},
		{
			name:     "b64-url-safe: only b64 chunk",
			chunk:    `bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q`,
			expected: `longer-encoded-secret-test`,
		},
		{
			name:     "b64-url-safe: mixed content",
			chunk:    `token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q`,
			expected: `token: longer-encoded-secret-test`,
		},
		{
			name:     "b64-url-safe: env var (looks like all b64 decodable but has `=` in the middle)",
			chunk:    `some-encoded-secret=dGVzdC1zZWNyZXQtdmFsdWU=`,
			expected: `some-encoded-secret=test-secret-value`,
		},
		{
			name:     "b64-url-safe: has longer b64 inside",
			chunk:    `some-encoded-secret="bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q"`,
			expected: `some-encoded-secret="longer-encoded-secret-test"`,
		},
		{
			name:     "b64-url-safe: hyphen url b64",
			chunk:    `Z2l0bGVha3M-PmZpbmRzLXNlY3JldHM`,
			expected: `gitleaks>>finds-secrets`,
		},
		{
			name:     "b64-url-safe: underscore url b64",
			chunk:    `YjY0dXJsc2FmZS10ZXN0LXNlY3JldC11bmRlcnNjb3Jlcz8_`,
			expected: `b64urlsafe-test-secret-underscores??`,
		},
		{
			name:     "invalid base64 string",
			chunk:    `a3d3fa7c2bb99e469ba55e5834ce79ee4853a8a3`,
			expected: `a3d3fa7c2bb99e469ba55e5834ce79ee4853a8a3`,
		},
		{
			name:     "url encoded value",
			chunk:    `secret%3D%22q%24%21%40%23%24%25%5E%26%2A%28%20asdf%22`,
			expected: `secret="q$!@#$%^&*( asdf"`,
		},
	}

	decoder := NewDecoder()

	// A helper to confirm a full decode
	fullDecode := func(data string) string {
		segments := []EncodedSegment{}

		for {
			data, segments = decoder.decode(data, segments)

			if len(segments) == 0 {
				return data
			}
		}
	}

	// Test base64 decoding
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, fullDecode(tt.chunk))
		})
	}

	// URL Encode the values to test URL decoding
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			percentEncodedChunk := url.PathEscape(tt.chunk)
			assert.Equal(t, tt.expected, fullDecode(percentEncodedChunk))
		})
	}
}

package detect

import (
	"github.com/stretchr/testify/require"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const secret = "AKIAIRYLJVKMPEGZMPJS"

type mockReader struct {
	data []byte
}

func (r *mockReader) Read(p []byte) (n int, err error) {
	// Copy data to the provided buffer.
	n = copy(p, r.data)

	// Return io.EOF along with the bytes.
	return n, io.EOF
}

// TestDetectReader tests the DetectReader function.
func TestDetectReader(t *testing.T) {
	tests := []struct {
		name          string
		reader        io.Reader
		bufSize       int
		findingsCount int
	}{
		{
			name:          "Test case - Reader returns n > 0 bytes and nil error",
			findingsCount: 1,
			reader:        strings.NewReader(secret),
		},
		{
			name:          "Test case - Reader returns n > 0 bytes and io.EOF error",
			findingsCount: 1,
			reader: &mockReader{
				data: []byte(secret),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detector, err := NewDetectorDefaultConfig()
			require.NoError(t, err)

			findings, err := detector.DetectReader(test.reader)
			require.NoError(t, err)

			assert.Equal(t, test.findingsCount, len(findings))
		})
	}
}

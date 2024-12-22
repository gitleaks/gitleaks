package detect

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

const secret = "AKIAIRYLJVKMPEGZMPJS"

type mockReader struct {
	data []byte
	read bool
}

func (r *mockReader) Read(p []byte) (n int, err error) {
	if r.read {
		return 0, io.EOF
	}

	// Copy data to the provided buffer.
	n = copy(p, r.data)
	r.read = true

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
			bufSize:       10,
			findingsCount: 1,
			reader:        strings.NewReader(secret),
		},
		{
			name:          "Test case - Reader returns n > 0 bytes and io.EOF error",
			bufSize:       10,
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

			findings, err := detector.DetectReader(test.reader, test.bufSize)
			require.NoError(t, err)

			assert.Equal(t, test.findingsCount, len(findings))
		})
	}
}

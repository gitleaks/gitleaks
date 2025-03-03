package detect

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/report"
)

const secret = "AKIAIRYLJVKMPEGZMPJS"

type mockReader struct {
	data []byte
	read bool

	errToReturn error
}

func (r *mockReader) Read(p []byte) (n int, err error) {
	if r.read {
		return 0, io.EOF
	}

	// Copy data to the provided buffer.
	n = copy(p, r.data)
	r.read = true
	if r.errToReturn != nil {
		return n, r.errToReturn
	}

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

func TestStreamDetectReader(t *testing.T) {
	tests := []struct {
		name          string
		reader        io.Reader
		bufSize       int
		expectedCount int
		expectError   bool
	}{
		{
			name:          "Single secret streaming",
			bufSize:       10,
			expectedCount: 1,
			reader:        strings.NewReader(secret),
			expectError:   false,
		},
		{
			name:          "Empty reader",
			bufSize:       10,
			expectedCount: 0,
			reader:        strings.NewReader(""),
			expectError:   false,
		},
		{
			name:          "Reader returns error",
			bufSize:       10,
			expectedCount: 0,
			reader:        iotest.ErrReader(errors.New("simulated read error")),
			expectError:   true,
		},
		{
			name:          "Multiple secrets with larger buffer",
			bufSize:       20,
			expectedCount: 2,
			reader:        strings.NewReader(secret + "\n" + secret),
			expectError:   false,
		},
		{
			name:          "Mock reader with EOF",
			bufSize:       10,
			expectedCount: 1,
			reader:        &mockReader{data: []byte(secret)},
			expectError:   false,
		},
		{
			name:          "Secret split across boundary",
			bufSize:       1, // 1KB buffer forces multiple reads
			expectedCount: 1,
			reader: io.MultiReader(
				strings.NewReader(secret[:len(secret)/2]),
				strings.NewReader(secret[len(secret)/2:])),
			expectError: false,
		},
		{
			name:          "Reader returns error after first read",
			bufSize:       1,
			expectedCount: 0,
			reader: &mockReader{
				data:        append(bytes.Repeat([]byte("blah"), 1000), []byte(secret)...),
				errToReturn: errors.New("simulated read error"),
			},
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detector, err := NewDetectorDefaultConfig()
			require.NoError(t, err)

			findingsCh, errCh := detector.StreamDetectReader(test.reader, test.bufSize)
			var findings []report.Finding
			for f := range findingsCh {
				findings = append(findings, f)
			}
			finalErr := <-errCh

			if test.expectError {
				require.Error(t, finalErr)
			} else {
				require.NoError(t, finalErr)
			}

			assert.Equal(t, test.expectedCount, len(findings))
		})
	}
}

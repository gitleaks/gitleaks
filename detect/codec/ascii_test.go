package codec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPrintableASCII(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "printable ASCII",
			input:    []byte("hello world"),
			expected: true,
		},
		{
			name:     "printable ASCII with tab",
			input:    []byte("hello\tworld"),
			expected: true,
		},
		{
			name:     "printable ASCII with newline",
			input:    []byte("hello\nworld"),
			expected: true,
		},
		{
			name:     "UTF-8 emoji",
			input:    []byte("🔓"),
			expected: true,
		},
		{
			name:     "UTF-8 accented chars",
			input:    []byte("café"),
			expected: true,
		},
		{
			name:     "mixed ASCII and UTF-8",
			input:    []byte("password🔓"),
			expected: true,
		},
		{
			name:     "UTF-8 Chinese characters",
			input:    []byte("你好世界"),
			expected: true,
		},
		{
			name:     "empty input",
			input:    []byte(""),
			expected: true,
		},
		{
			name:     "invalid UTF-8 sequence",
			input:    []byte{0x80, 0x81, 0x82},
			expected: false,
		},
		{
			name:     "null byte",
			input:    []byte{0x00},
			expected: false,
		},
		{
			name:     "control character (bell)",
			input:    []byte{0x07},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPrintableASCII(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

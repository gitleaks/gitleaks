package sources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gabriel-vasile/mimetype"
)

var minimalPNG = []byte{
	0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
	0x00, 0x00, 0x00, 0x0D, // length = 13
	0x49, 0x48, 0x44, 0x52, // "IHDR"
	0x00, 0x00, 0x00, 0x01, // width: 1
	0x00, 0x00, 0x00, 0x01, // height: 1
	0x08,                   // bit depth: 8
	0x02,                   // color type: truecolor
	0x00,                   // compression
	0x00,                   // filter
	0x00,                   // interlace
	0x90, 0x77, 0x53, 0xDE, // CRC
}

// expected values: whether isHumanReadable should return true or false
var testCases = map[string]struct {
	content  string
	expected bool
}{
	"test.json": {`{"key":"value"}`, true},
	"test.xml":  {`<root><foo/></root>`, true},
	"test.yaml": {"foo: bar\n", true},
	"test.toml": {"foo=\"bar\"\n", true},
	"test.txt":  {"hello world\n", true},
	"test.sh":   {"#!/bin/bash\necho hi\n", true},
	"test.png":  {string(minimalPNG), false},
	"test.pdf":  {"%PDF-1.4\n", false},
}

func TestIsHumanReadable(t *testing.T) {
	tmpdir := t.TempDir()

	for name, tc := range testCases {
		path := filepath.Join(tmpdir, name)
		if err := os.WriteFile(path, []byte(tc.content), 0644); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read %s: %v", name, err)
		}

		m := mimetype.Detect(data)
		got := isHumanReadable(m)

		if got != tc.expected {
			t.Errorf("%s: got %v for MIME %s, expected %v",
				name, got, m.String(), tc.expected)
		}
	}
}

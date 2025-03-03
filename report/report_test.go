package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const expectPath = "../testdata/expected/"
const templatePath = "../testdata/report/"

func TestWriteStdout(t *testing.T) {
	// Arrange
	reporter := JsonReporter{}
	buf := testWriter{
		bytes.NewBuffer(nil),
	}
	findings := []Finding{
		{
			RuleID: "test-rule",
		},
	}

	// Act
	err := reporter.Write(buf, findings)
	require.NoError(t, err)
	got := buf.Bytes()

	// Assert
	assert.NotEmpty(t, got)
}

type testWriter struct {
	*bytes.Buffer
}

func (t testWriter) Close() error {
	return nil
}

// lineEndingReplacer normalizes CRLF to LF so tests pass on Windows.
var lineEndingReplacer = strings.NewReplacer(
	"\\r\\n", "\\n",
	"\r", "",
	"\\r", "",
)

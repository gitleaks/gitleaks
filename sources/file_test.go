package sources

import (
	"bufio"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fragmentsOf returns the raw content of each fragment yielded for content.
func fragmentsOf(t *testing.T, content string) []string {
	t.Helper()

	var raws []string
	file := &File{Path: "file.txt"}
	err := file.fileFragments(
		context.Background(),
		bufio.NewReader(strings.NewReader(content)),
		func(fragment Fragment, err error) error {
			require.NoError(t, err)
			raws = append(raws, fragment.Raw)
			return nil
		},
	)
	require.NoError(t, err)

	return raws
}

func Test_fileFragments_filetype(t *testing.T) {
	// The first line spans more than one chunk, so no newline has been read
	// yet when the second chunk starts.
	firstLine := strings.Repeat("a", 2*defaultBufferSize)
	plain := fragmentsOf(t, firstLine+"\nafter\n")
	require.Greater(t, len(plain), 1, "the first line must span more than one chunk")
	boundary := len(plain[0])

	t.Run("binary signature at the start of a later chunk", func(t *testing.T) {
		content := firstLine[:boundary] + "MZ" + firstLine[boundary+2:] + "\nafter\n"
		got := strings.Join(fragmentsOf(t, content), "")

		// Compare lengths first to keep the failure message short.
		require.Equal(t, len(content), len(got), "the fragments must cover the whole file")
		require.True(t, content == got, "the fragments must match the file content")
	})

	t.Run("binary signature at the start of the file", func(t *testing.T) {
		content := "MZ" + firstLine[2:] + "\nafter\n"

		require.Empty(t, fragmentsOf(t, content))
	})
}

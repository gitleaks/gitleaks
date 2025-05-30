package sources

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"path/filepath"
	"runtime"

	"github.com/mholt/archives"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

const maxPeekSize = 25 * 1_000 // 10kb
var isWhitespace [256]bool
var isWindows = runtime.GOOS == "windows"

func init() {
	// define whitespace characters
	isWhitespace[' '] = true
	isWhitespace['\t'] = true
	isWhitespace['\n'] = true
	isWhitespace['\r'] = true
}

// isArchive does a light check to see if the provided path is an archive or
// compressed file. The File source already does this, so this exists mainly
// to avoid expensive calls before sending things to the File source
func isArchive(ctx context.Context, path string) bool {
	format, _, err := archives.Identify(ctx, path, nil)
	return err == nil && format != nil
}

// shouldSkipPath checks a path against all the allowlists to see if it can
// be skipped
func shouldSkipPath(cfg *config.Config, path string) bool {
	if cfg == nil {
		logging.Trace().Str("path", path).Msg("not skipping path because config is nil")
		return false
	}

	for _, a := range cfg.Allowlists {
		if a.PathAllowed(path) ||
			// TODO: Remove this in v9.
			// This is an awkward hack to mitigate https://github.com/gitleaks/gitleaks/issues/1641.
			(isWindows && a.PathAllowed(filepath.ToSlash(path))) {
			return true
		}
	}

	return false
}

// readUntilSafeBoundary consumes |f| until it finds two consecutive `\n` characters, up to |maxPeekSize|.
// This hopefully avoids splitting. (https://github.com/gitleaks/gitleaks/issues/1651)
func readUntilSafeBoundary(r *bufio.Reader, n int, maxPeekSize int, peekBuf *bytes.Buffer) error {
	if peekBuf.Len() == 0 {
		return nil
	}

	// Does the buffer end in consecutive newlines?
	var (
		data         = peekBuf.Bytes()
		lastChar     = data[len(data)-1]
		newlineCount = 0 // Tracks consecutive newlines
	)

	if isWhitespace[lastChar] {
		for i := len(data) - 1; i >= 0; i-- {
			lastChar = data[i]
			if lastChar == '\n' {
				newlineCount++

				// Stop if two consecutive newlines are found
				if newlineCount >= 2 {
					return nil
				}
			} else if isWhitespace[lastChar] {
				// The presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count.
				// (Intentionally do nothing.)
			} else {
				break
			}
		}
	}

	// If not, read ahead until we (hopefully) find some.
	newlineCount = 0
	for {
		data = peekBuf.Bytes()
		// Check if the last character is a newline.
		lastChar = data[len(data)-1]
		if lastChar == '\n' {
			newlineCount++

			// Stop if two consecutive newlines are found
			if newlineCount >= 2 {
				break
			}
		} else if isWhitespace[lastChar] {
			// The presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count.
			// (Intentionally do nothing.)
		} else {
			newlineCount = 0 // Reset if a non-newline character is found
		}

		// Stop growing the buffer if it reaches maxSize
		if (peekBuf.Len() - n) >= maxPeekSize {
			break
		}

		// Read additional data into a temporary buffer
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		peekBuf.WriteByte(b)
	}
	return nil
}

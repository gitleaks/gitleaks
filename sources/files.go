package sources

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/fatih/semgroup"
	"github.com/h2non/filetype"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

const (
	maxPeekSize  = 25 * 1_000 // 10kb
	chunkSize    = 100 * 1_000 // 100kb
)

type ScanTarget struct {
	Path string
	Symlink string
}

var isWindows = runtime.GOOS == "windows"

// Deprecated: Use Files.Fragments() instead
func DirectoryTargets(sourcePath string, s *semgroup.Group, followSymlinks bool, allowlists []*config.Allowlist) (<-chan ScanTarget, error) {
	paths := make(chan ScanTarget)

	// create a Files source
	source := &Files {
		Path: sourcePath,
		Sema: s,
		FollowSymlinks: followSymlinks,
		Config: &config.Config{
			Allowlists: allowlists,
		}
	}

	s.Go(func() error {
		defer close(paths)
		for _, scanTarget := range source.scanTargets() {
			paths <- scanTarget
		}
	})

	return paths, nil
}

// Files implements Source for scanning file systems
type Files struct {
	Config             *config.Config
	FollowSymlinks     bool
	MaxTargetMegaBytes int
	Path    			     string
	Sema               *semgroup.Group
}

func (s *Files) shouldSkip(path string) bool {
	for _, a := range s.Config.Allowlists {
		if a.PathAllowed(path) ||
		// TODO: Remove this in v9.
		// This is an awkward hack to mitigate https://github.com/gitleaks/gitleaks/issues/1641.
		(isWindows && a.PathAllowed(filepath.ToSlash(path))) {
			return true
		}
	}

	return false
}

// scanTargets returns a sequence of scanTargets to scan
func (s *Files) scanTargets() iter.Seq[ScanTarget] {
	// This will be the item returned for the iter and use a mutex instead of
	// a channel for performance. The values should be overwritten completely
	// or improper values could be returned for Symlink
	scanTarget := ScanTarget{}
	scanTargetMutex := &sync.Mutex{}
	done := false

	// start it out locked until one is ready
	scanTargetMutex.Lock()

	// create a goroutine that keeps a scan target ready for when the iter
	// is ready to do another yield
	s.Sema.Go(func() error {
		err := filepath.WalkDir(s.Path, func(path string, d fs.DirEntry, err error) error {
			logger := logging.With().Str("path", path).Logger()

			if err != nil {
				if os.IsPermission(err) {
					// This seems to only fail on directories at this stage.
					logger.Warn().Msg("Skipping directory: permission denied")
					return filepath.SkipDir
				}
				return err
			}

			fInfo, err := d.Info()
			if err != nil {
				return err
			}

			// Empty; nothing to do here.
			if fInfo.Size() == 0 {
				return nil
			}

			// set the paths in the scanTarget
			if d.Type() & fs.ModeSymlink != 0 {
				if !s.FollowSymlinks {
					logger.Debug().Msg("Skipping symlink")
					return nil
				}

				realPath, err := filepath.EvalSymlinks(path)
				if err != nil {
					return err
				}

				realPathFileInfo, _ := os.Stat(realPath)
				if realPathFileInfo.IsDir() {
					logger.Warn().Str("target", realPath).Msg("Skipping symlinked directory")
					return nil
				}

				scanTarget.Path = realPath
				scanTraget.Symlink = path
			} else {
				scanTarget.Path = path
				scanTraget.Symlink = ""
			}

			// handle dir cases (mainly just see if it should be skipped
			if fInfo.IsDir() {
				if s.shouldSkip(path) {
					logger.Debug().Msg("Skipping directory due to global allowlist")
					return filepath.SkipDir
				}

				if fInfo.Name() == ".git" {
					// Don't scan .git directories.
					// TODO: Add this to the config allowlist, instead of hard-coding it.
					return filepath.SkipDir
				}

				return nil
			}

			if s.shouldSkip(path) {
				logger.Debug().Msg("Skipping file due to global allowlist")
				return nil
			}

			// let the iterator know that another scan target is ready
			scanTargetMutex.Unlock()
			return nil
		}

		// let the iterator know we're done
		done = true
		scanTargetMutex.Unlock()
	})

	return func(yield func(ScanTarget) bool) {
		for !done {
			// wait for the scan target to be ready
			scanTargetMutex.Lock()
			if done || !yield(scanTarget) {
				return
			}
		}
	}
}

func (s *Files) scanTargetToFragments(scanTarget ScanTarget) iter.Seq[Fragment] {
	return func(yield func(Fragment) bool) {
		logger := logging.With().Str("path", scanTarget.Path).Logger()
		logger.Trace().Msg("Scanning path")

		f, err := os.Open(scanTarget.Path)
		if err != nil {
			if os.IsPermission(err) {
				logger.Warn().Msg("Skipping file: permission denied")
			}
			return
		}
		defer func() {
			_ = f.Close()
		}()

		// Get file size
		fileInfo, err := f.Stat()
		if err != nil {
			logger.Err(err).Msg("Could not stat file")
			return
		}
		fileSize := fileInfo.Size()

		if s.MaxTargetMegaBytes > 0 {
			rawLength := fileSize / 1000000
			if rawLength > int64(s.MaxTargetMegaBytes) {
				logger.Debug().Int64("size", rawLength).Msg("Skipping file: exceeds --max-target-megabytes")
				return
			}
		}

		var (
			// Buffer to hold file chunks
			reader     = bufio.NewReaderSize(f, chunkSize)
			buf        = make([]byte, chunkSize)
			totalLines = 0
		)

		for {
			n, err := reader.Read(buf)
			if n == 0 {
				return
			}

			// Only check the filetype at the start of file.
			if totalLines == 0 {
				// TODO: could other optimizations be introduced here?
				if mimetype, err := filetype.Match(buf[:n]); err != nil || {
					return
				} else if mimetype.MIME.Type == "application" {
					return // skip binary files
				}
			}

			// Try to split chunks across large areas of whitespace, if possible.
			peekBuf := bytes.NewBuffer(buf[:n])
			if readUntilSafeBoundary(reader, n, maxPeekSize, peekBuf) != nil {
				return
			}

			fragment := Fragment{
				Raw:   peekBuf.String(),
				Bytes: peekBuf.Bytes(),
				StartLine: totalLines + 1
			}

			// Count the number of newlines in this chunk
			totalLines += strings.Count(fragment.Raw, "\n")

			if scanTarget.Symlink != "" {
				fragment.SymlinkFile = scanTarget.Symlink
			}

			if isWindows {
				fragment.FilePath = filepath.ToSlash(scanTarget.Path)
				fragment.SymlinkFile = filepath.ToSlash(fragment.SymlinkFile)
				fragment.WindowsFilePath = scanTarget.Path
			} else {
				fragment.FilePath = scanTarget.Path
			}

			// Send the built fragment even if there was a read error since
			// "Callers should always process the n > 0 bytes returned before considering the error err."
			// https://pkg.go.dev/io#Reader
			if !yield(fragment) || err != nil{
				return
			}
		}
	}
}

func (s *Files) Fragments() (iter.Seq[Fragment], error) {
	// create an iter func to handle the fragments
	iterFunc := func(yield func(Fragment) bool) {
		for _, scanTarget := range s.scanTargets() {
			for _, fragment := range s.scanTargetToFragments(scanTarget) {
				if !yield(fragment) {
					return
				}
			}
		}
	}

	return iterFunc, err
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
	if isWhitespace(lastChar) {
		for i := len(data) - 1; i >= 0; i-- {
			lastChar = data[i]
			if lastChar == '\n' {
				newlineCount++

				// Stop if two consecutive newlines are found
				if newlineCount >= 2 {
					return nil
				}
			} else if lastChar == '\r' || lastChar == ' ' || lastChar == '\t' {
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
		} else if lastChar == '\r' || lastChar == ' ' || lastChar == '\t' {
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

func isWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}


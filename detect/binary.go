package detect

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mholt/archives"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
)

// ignoredExtensions are file types that will never reasonably contain secrets.
var ignoredExtensions = map[string]struct{}{
	// Audio (https://en.wikipedia.org/wiki/Audio_file_format)
	".aac":  {},
	".flac": {},
	".mp3":  {},
	".ogg":  {},
	".wav":  {},

	// Images (https://developer.mozilla.org/en-US/docs/Web/Media/Formats/Image_types)
	".avif":    {},
	".bmp":     {},
	".eps":     {},
	".gif":     {},
	".gifv":    {},
	".ico":     {},
	".monopic": {},
	".jpg":     {},
	".jpeg":    {},
	".png":     {},
	".svg":     {},
	".tif":     {},
	".tiff":    {},
	".webp":    {},

	// Videos (https://en.wikipedia.org/wiki/Video_file_format)
	".3gp":  {},
	".avi":  {},
	".flv":  {},
	".mkv":  {},
	".mov":  {},
	".mp4":  {},
	".mpg":  {},
	".mpeg": {},
	".swf":  {},
	".webm": {},

	// Fonts
	".eot":   {},
	".otf":   {},
	".ttf":   {},
	".woff":  {},
	".woff2": {},

	// Other
	".psd": {},
	".dia": {}, // https://en.wikipedia.org/wiki/Dia_(software)
}

// unsupportedExtensions are file types that may contain secrets,
// however, they require special processing that the engine is not capable of.
var unsupportedExtensions = map[string]struct{}{
	// Archives (https://en.wikipedia.org/wiki/List_of_archive_formats)
	//".7z":  {},
	//".bz2": {},
	//".gz":     {},
	//".gzip":   {},
	//".rar":    {},
	//".tar.bz": {},
	//".tar.gz":  {},
	//".tar.xz":  {},
	//".tar.zst": {},
	//".tgz":     {},
	//".zip":     {},

	// Java (technically these are ZIPs)
	//".jar": {},
	//".ear": {},
	//".war": {},

	// Cryptographic keys
	".cer": {},
	".der": {},
	".gpg": {},
	".jks": {},
	".p12": {},
	".pfx": {},
}

var count = map[string]*atomic.Uint64{}

// TODO: Check mimetype, some files don't have extensions.
func shouldScanBinaryFile(filePath string) (bool, string) {
	ext := strings.ToLower(filepath.Ext(filePath))
	if _, ok := ignoredExtensions[ext]; ok {
		return false, "ignored"
	}
	if c, ok := count[ext]; ok {
		c.Add(1)
	} else {
		count[ext] = &atomic.Uint64{}
		count[ext].Add(1)
	}
	if _, ok := unsupportedExtensions[ext]; ok {
		return false, "unsupported"
	}
	return true, ""
}

func (d *Detector) handleFile(ctx context.Context, path string, r io.Reader, creatTempFile bool) ([]report.Finding, error) {
	var (
		start    = time.Now()
		findings []report.Finding
		logger   = logging.Ctx(ctx)
	)

	filename := filepath.Base(path)
	format, r2, err := archives.Identify(ctx, filename, r)
	if err != nil {
		return findings, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, r2)
	}()

	logger.Info().
		Str("mediatype", format.MediaType()).
		Str("extension", format.Extension()).
		Msg("Detected file")

	seeker, ok := r2.(archives.ReaderAtSeeker)
	if !ok {
		logger.Info().Msgf("Fuck! not a readeratseker!")
		return findings, nil
	}

	//var walkRoot string
	if creatTempFile && false {
		// Open the file for writing
		file, err := os.CreateTemp("", "gitleaks-*.tar.gz")
		if err != nil {
			return findings, fmt.Errorf("failed to create temp file: %w", err)
		}
		defer func() {
			_ = file.Close()
			_ = os.Remove(file.Name())
		}()
		logger.Debug().Msgf("Created temp file %s", file.Name())

		// Create a buffered writer
		writer := bufio.NewWriter(file)
		defer writer.Flush()

		// Copy from the reader to the buffered writer
		if _, err = io.Copy(writer, r2); err != nil {
			return findings, fmt.Errorf("failed to write to file: %w", err)
		}

		//walkRoot = file.Name()
	} else {
		//walkRoot = path
	}

	//logger.Info().
	//	Str("path", path).
	//	Str("walk_path", walkRoot).
	//	Str("mediatype", format.MediaType()).
	//	Msg("Walking directory...")

	// https://github.com/mholt/archives?tab=readme-ov-file#traverse-into-archives-while-walking
	// TODO: Extract the file. It's easy-peasy!
	// TODO: this can cause OOM...
	//fsys := &archives.DeepFS{Root: walkRoot}
	afs, err := archives.FileSystem(ctx, filename, seeker)
	if err != nil {
		return findings, err
	}
	err = fs.WalkDir(afs, ".", func(fpath string, dir fs.DirEntry, err error) error {
		if err != nil {
			logger.Err(err).Msgf("Failed to walk file %s", fpath)
			return err
		} else if dir.IsDir() {
			return nil
		}

		//if fpath != "." {
		//	logger.Info().Msgf("WalkDir: found file %s", fpath)
		//}
		f, err := afs.Open(fpath)
		if err != nil {
			logger.Err(err).Msgf("Failed to open file %s", fpath)
			return fmt.Errorf("failed to open fsys: %w", err)
		}
		defer func() {
			_, _ = io.Copy(io.Discard, f)
			_ = f.Close()
		}()

		fileFindings, err := d.DetectReader(f, fpath)
		if err != nil {
			return fmt.Errorf("failed to detect reader: %w", err)
		}
		for _, finding := range fileFindings {
			findings = append(findings, finding)
		}
		return nil
	})
	if err != nil {
		logger.Error().Err(err).Msgf("Failed to walk dir")
	}

	logger.Info().Str("took", time.Since(start).String()).Msg("Scanned file")
	return findings, nil
}

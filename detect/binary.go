package detect

import (
	"errors"
	"github.com/mholt/archiver/v4"
	"github.com/rs/zerolog/log"
	"io"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	".7z":      {},
	".bz2":     {},
	".gz":      {},
	".gzip":    {},
	".rar":     {},
	".tar.bz":  {},
	".tar.gz":  {},
	".tar.xz":  {},
	".tar.zst": {},
	".tgz":     {},
	".zip":     {},

	// Java (technically these are ZIPs)
	".jar": {},
	".ear": {},
	".war": {},

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

func handleFile(filename string, r io.Reader) error {
	format, _, err := archiver.Identify(filename, r)
	if err != nil {
		if errors.Is(err, archiver.ErrNoMatch) {
			return nil
		}
		return err
	}

	log.Info().Str("path", filename).
		Str("format", format.Name()).
		Msg("File identified.")

	// TODO: Extract the file. It's easy-peasy!

	return nil
}

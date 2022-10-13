package report

import (
	"encoding/csv"
	"io"
	"strconv"
)

// writeCsv writes the list of findings to a writeCloser.
func writeCsv(f []Finding, w io.WriteCloser) error {
	if len(f) == 0 {
		return nil
	}
	defer w.Close()
	cw := csv.NewWriter(w)
	err := cw.Write([]string{"RuleID",
		"Commit",
		"File",
		"SymlinkFile",
		"Secret",
		"Match",
		"StartLine",
		"EndLine",
		"StartColumn",
		"EndColumn",
		"Author",
		"Message",
		"Date",
		"Email",
		"Fingerprint",
	})
	if err != nil {
		return err
	}
	for _, f := range f {
		err = cw.Write([]string{f.RuleID,
			f.Commit,
			f.File,
			f.SymlinkFile,
			f.Secret,
			f.Match,
			strconv.Itoa(f.StartLine),
			strconv.Itoa(f.EndLine),
			strconv.Itoa(f.StartColumn),
			strconv.Itoa(f.EndColumn),
			f.Author,
			f.Message,
			f.Date,
			f.Email,
			f.Fingerprint,
		})
		if err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}

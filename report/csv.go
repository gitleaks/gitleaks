package report

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
)

type CsvReporter struct {
}

var _ Reporter = (*CsvReporter)(nil)

func (r *CsvReporter) Write(w io.WriteCloser, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}

	var (
		cw  = csv.NewWriter(w)
		err error
	)
	columns := []string{"RuleID",
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
		"Tags",
	}
	// A miserable attempt at "omitempty" so tests don't yell at me.
	if findings[0].Link != "" {
		columns = append(columns, "Link")
	}

	if err = cw.Write(columns); err != nil {
		return err
	}
	for _, f := range findings {
		row := []string{f.RuleID,
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
			strings.Join(f.Tags, " "),
		}
		if findings[0].Link != "" {
			row = append(row, f.Link)
		}

		if err = cw.Write(row); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}

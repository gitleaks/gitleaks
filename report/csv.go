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

// csvInjectionLeadingChars are characters that spreadsheet applications such as
// Excel, LibreOffice Calc, and Google Sheets may interpret as the start of a
// formula. A cell that begins with one of these can trigger CSV/formula
// injection (CWE-1236) when a report generated from an untrusted repository is
// later opened in a spreadsheet. Findings contain attacker-influenced data
// (commit author/email/message, file paths, and the matched content), so each
// cell value is neutralized before it is written.
// See https://owasp.org/www-community/attacks/CSV_Injection
func sanitizeCSVCell(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	}
	return value
}

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
		row := []string{sanitizeCSVCell(f.RuleID),
			sanitizeCSVCell(f.Commit),
			sanitizeCSVCell(f.File),
			sanitizeCSVCell(f.SymlinkFile),
			sanitizeCSVCell(f.Secret),
			sanitizeCSVCell(f.Match),
			strconv.Itoa(f.StartLine),
			strconv.Itoa(f.EndLine),
			strconv.Itoa(f.StartColumn),
			strconv.Itoa(f.EndColumn),
			sanitizeCSVCell(f.Author),
			sanitizeCSVCell(f.Message),
			sanitizeCSVCell(f.Date),
			sanitizeCSVCell(f.Email),
			sanitizeCSVCell(f.Fingerprint),
			sanitizeCSVCell(strings.Join(f.Tags, " ")),
		}
		if findings[0].Link != "" {
			row = append(row, sanitizeCSVCell(f.Link))
		}

		if err = cw.Write(row); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}

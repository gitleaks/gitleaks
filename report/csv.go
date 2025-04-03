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
	columns := []string{"ID",
		"RuleID",
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
		"IsSubFinding",
		"SubFindings",
	}
	// A miserable attempt at "omitempty" so tests don't yell at me.
	if findings[0].Link != "" {
		columns = append(columns, "Link")
	}

	if err = cw.Write(columns); err != nil {
		return err
	}

	findingId := 0
	for _, f := range findings {
		var subFindings [][]string
		var subFindingIds []string
		findingId += 1

		row := []string{strconv.Itoa(findingId),
			f.RuleID,
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
			strconv.FormatBool(f.IsSubFinding),
		}

		for _, sf := range f.SubFindings {
			findingId += 1
			row := []string{strconv.Itoa(findingId),
				sf.RuleID,
				sf.Commit,
				sf.File,
				sf.SymlinkFile,
				sf.Secret,
				sf.Match,
				strconv.Itoa(sf.StartLine),
				strconv.Itoa(sf.EndLine),
				strconv.Itoa(sf.StartColumn),
				strconv.Itoa(sf.EndColumn),
				sf.Author,
				sf.Message,
				sf.Date,
				sf.Email,
				sf.Fingerprint,
				strings.Join(sf.Tags, " "),
				strconv.FormatBool(sf.IsSubFinding),
				"",
			}
			if findings[0].Link != "" {
				row = append(row, sf.Link)
			}

			subFindings = append(subFindings, row)
			subFindingIds = append(subFindingIds, strconv.Itoa(findingId))
		}

		row = append(row, strings.Join(subFindingIds, " "))
		if findings[0].Link != "" {
			row = append(row, f.Link)
		}

		if err = cw.Write(row); err != nil {
			return err
		}

		for _, subFinding := range subFindings {
			if err = cw.Write(subFinding); err != nil {
				return err
			}
		}
	}

	cw.Flush()
	return cw.Error()
}

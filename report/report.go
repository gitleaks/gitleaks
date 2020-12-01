package report

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zricethezav/gitleaks/v7/options"
)

// Report is a container for leaks and number of commits scanned
type Report struct {
	Leaks   []Leak
	Commits int
}

// WriteReport accepts a report and options and will write a report if --report has been set
func WriteReport(report Report, opts options.Options) error {
	log.Info("commits scanned: ", report.Commits)
	if len(report.Leaks) != 0 {
		log.Warn("leaks found: ", len(report.Leaks))
	} else {
		log.Info("No leaks found")
		return nil
	}

	if opts.Report == "" {
		return nil
	}

	if opts.Redact {
		var redactedLeaks []Leak
		for _, leak := range report.Leaks {
			redactedLeaks = append(redactedLeaks, RedactLeak(leak))
		}
		report.Leaks = redactedLeaks
	}

	file, err := os.Create(opts.Report)
	if err != nil {
		return err
	}
	defer file.Close()

	if opts.Report != "" {
		switch opts.ReportFormat {
		case "json":
			encoder := json.NewEncoder(file)
			encoder.SetIndent("", " ")
			err = encoder.Encode(report.Leaks)
			if err != nil {
				return err
			}
		case "csv":
			w := csv.NewWriter(file)
			_ = w.Write([]string{"repo", "line", "commit", "offender", "rule", "tags", "commitMsg", "author", "email", "file", "date"})
			for _, leak := range report.Leaks {
				w.Write([]string{leak.Repo, leak.Line, leak.Commit, leak.Offender, leak.Rule, leak.Tags, leak.Message, leak.Author, leak.Email, leak.File, leak.Date.Format(time.RFC3339)})
			}
			w.Flush()
		case "sarif":

		}

	}

	return nil
}

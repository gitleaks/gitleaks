package scan

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
	"github.com/zricethezav/gitleaks/v7/version"
)

// Report is a container for leaks and number of commits scanned
type Report struct {
	Leaks   []Leak
	Commits int
}

// WriteReport accepts a report and options and will write a report if --report has been set
func WriteReport(report Report, opts options.Options, cfg config.Config) error {
	if !(opts.NoGit || opts.CheckUncommitted()) {
		logrus.Info("commits scanned: ", report.Commits)
	}
	if len(report.Leaks) != 0 {
		logrus.Warn("leaks found: ", len(report.Leaks))
	} else {
		logrus.Info("No leaks found")
		return nil
	}

	if opts.Report == "" {
		return nil
	} else {
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
		defer rable(file.Close)

		switch strings.ToLower(opts.ReportFormat) {
		case "json":
			encoder := json.NewEncoder(file)
			encoder.SetIndent("", " ")
			err = encoder.Encode(report.Leaks)
			if err != nil {
				return err
			}
		case "csv":
			w := csv.NewWriter(file)
			err = w.Write([]string{"repo", "line", "commit", "offender", "leakURL", "rule", "tags", "commitMsg", "author", "email", "file", "date"})
			if err != nil {
				return err
			}
			for _, leak := range report.Leaks {
				err := w.Write([]string{leak.Repo, leak.Line, leak.Commit, leak.Offender, leak.LeakURL, leak.Rule, leak.Tags, leak.Message, leak.Author, leak.Email, leak.File, leak.Date.Format(time.RFC3339)})
				if err != nil {
					return err
				}
			}
			w.Flush()
		case "sarif":
			s := Sarif{
				Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
				Version: "2.1.0",
				Runs: []Runs{
					{
						Tool: Tool{
							Driver: Driver{
								Name:            "Gitleaks",
								SemanticVersion: version.Version,
								Rules:           configToRules(cfg),
							},
						},
						Results: leaksToResults(report.Leaks),
					},
				},
			}
			encoder := json.NewEncoder(file)
			encoder.SetIndent("", " ")
			err = encoder.Encode(s)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

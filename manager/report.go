package manager

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"time"

	"github.com/zricethezav/gitleaks/v5/version"

	log "github.com/sirupsen/logrus"
)

// Report saves gitleaks leaks to a json specified by --report={report.json}
func (manager *Manager) Report() error {
	close(manager.leakChan)
	close(manager.metadata.timings)

	if log.IsLevelEnabled(log.DebugLevel) {
		manager.DebugOutput()
	}

	if manager.Opts.Report != "" {
		if len(manager.GetLeaks()) == 0 {
			log.Infof("no leaks found, skipping writing report")
			return nil
		}
		file, err := os.Create(manager.Opts.Report)
		if err != nil {
			return err
		}

		switch manager.Opts.ReportFormat {
		case "json":
			encoder := json.NewEncoder(file)
			encoder.SetIndent("", " ")
			err = encoder.Encode(manager.leaks)
			if err != nil {
				return err
			}
		case "csv":
			w := csv.NewWriter(file)
			_ = w.Write([]string{"repo", "line", "commit", "offender", "rule", "tags", "commitMsg", "author", "email", "file", "date"})
			for _, leak := range manager.GetLeaks() {
				w.Write([]string{leak.Repo, leak.Line, leak.Commit, leak.Offender, leak.Rule, leak.Tags, leak.Message, leak.Author, leak.Email, leak.File, leak.Date.Format(time.RFC3339)})
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
								Rules:           manager.configToRules(),
							},
						},
						Results: manager.leaksToResults(),
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
		_ = file.Close()

		log.Infof("report written to %s", manager.Opts.Report)
	}
	return nil
}


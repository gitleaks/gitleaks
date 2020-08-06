package manager

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/zricethezav/gitleaks/v5/version"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

type Sarif struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Runs `json:"runs"`
}

type ShortDescription struct {
	Text string `json:"text"`
}
type FullDescription struct {
	Text string `json:"text"`
}
type Rules struct {
	ID                   string               `json:"id"`
	Name                 string               `json:"name"`
	ShortDescription     ShortDescription     `json:"shortDescription"`
	FullDescription      FullDescription      `json:"fullDescription"`
}
type Driver struct {
	Name            string  `json:"name"`
	SemanticVersion string  `json:"semanticVersion"`
	Rules           []Rules `json:"rules"`
}
type Tool struct {
	Driver Driver `json:"driver"`
}
type Message struct {
	Text string `json:"text"`
}
type ArtifactLocation struct {
	URI string `json:"uri"`
}
type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndColumn   int `json:"endColumn"`
}
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}
type Locations struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}
type PartialFingerprints struct {
	PrimaryLocationLineHash string `json:"primaryLocationLineHash"`
}
type Results struct {
	Message             Message             `json:"message"`
	Locations           []Locations         `json:"locations"`
	PartialFingerprints PartialFingerprints `json:"partialFingerprints"`
}
type Runs struct {
	Tool    Tool      `json:"tool"`
	Results []Results `json:"results"`
}

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
				Schema:  "",
				Version: "",
				Runs: []Runs{
					{
						Tool: Tool{
							Driver: Driver{
								Name:            "Gitleaks",
								SemanticVersion: version.Version,
								Rules: manager.configToRules(),
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

// TODO
func (m *Manager) configToRules() []Rules {
	var rules []Rules
	for _, rule := range m.Config.Rules {
		fullDescription := fmt.Sprintf("%s using ", rule.Description)
		if rule.Regex != nil {
			fullDescription += fmt.Sprintf(" regex: %s", rule.Regex.String())
		}
		if len(rule.Entropies) != 0 {
			fullDescription += fmt.Sprintf(" entropies: %v", rule.Entropies)
		}
		if rule.FileNameRegex != nil {
			fullDescription += fmt.Sprintf(" fileNameRegex: %s", rule.FileNameRegex.String())
		}
		if rule.FilePathRegex != nil {
			fullDescription += fmt.Sprintf(" filePathRegex: %s", rule.FilePathRegex.String())
		}
		if len(rule.Allowlist) != 0 {
			fullDescription += fmt.Sprintf("and including allowlist:")
			for _, a := range rule.Allowlist {
				if a.Regex != nil {
					fullDescription += fmt.Sprintf(" regex: %s", a.Regex.String())
				}
				if a.File != nil {
					fullDescription += fmt.Sprintf(" fileNameRegex: %s", a.File.String())
				}
				if a.Path != nil {
					fullDescription += fmt.Sprintf(" filePathRegex: %s", a.File.String())
				}
			}
		}

		rules = append(rules, Rules{
			ID:   rule.Description,
			Name: rule.Description,
			ShortDescription: ShortDescription{
				Text: rule.Description,
			},
			FullDescription: FullDescription{
				Text: fullDescription,
			},
		})

	}
	return rules
}

func (m *Manager) leaksToResults() []Results {
	var results []Results
	for _, leak := range m.leaks {
		results = append(results, Results{
			Message:             Message{
				Text: ,
			},
			Locations:           nil,
			PartialFingerprints: PartialFingerprints{},
		})
		
	}
	
	return results
}


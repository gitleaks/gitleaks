package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/zricethezav/gitleaks/v8/config"
)

type SarifReporter struct {
	OrderedRules []config.Rule
}

var _ Reporter = (*SarifReporter)(nil)

func (r *SarifReporter) Write(w io.WriteCloser, findings []Finding) error {
	sarif := Sarif{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    r.getRuns(findings),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(sarif)
}

func (r *SarifReporter) getRuns(findings []Finding) []Runs {
	return []Runs{
		{
			Tool:    r.getTool(),
			Results: getResults(findings),
		},
	}
}

func (r *SarifReporter) getTool() Tool {
	tool := Tool{
		Driver: Driver{
			Name:            driver,
			SemanticVersion: version,
			InformationUri:  "https://github.com/gitleaks/gitleaks",
			Rules:           r.getRules(),
		},
	}

	// if this tool has no rules, ensure that it is represented as [] instead of null/nil
	if hasEmptyRules(tool) {
		tool.Driver.Rules = make([]Rules, 0)
	}

	return tool
}

func hasEmptyRules(tool Tool) bool {
	return len(tool.Driver.Rules) == 0
}

func (r *SarifReporter) getRules() []Rules {
	// TODO	for _, rule := range cfg.Rules {
	var rules []Rules
	for _, rule := range r.OrderedRules {
		rules = append(rules, Rules{
			ID: rule.RuleID,
			Description: ShortDescription{
				Text: rule.Description,
			},
		})
	}
	return rules
}

func messageText(f Finding) string {
	if f.Commit == "" {
		return fmt.Sprintf("%s has detected secret for file %s.", f.RuleID, f.File)
	}

	return fmt.Sprintf("%s has detected secret for file %s at commit %s.", f.RuleID, f.File, f.Commit)

}

func getResults(findings []Finding) []Results {
	results := []Results{}
	for _, f := range findings {
		r := Results{
			Message: Message{
				Text: messageText(f),
			},
			RuleId:    f.RuleID,
			Locations: getLocation(f),
			// This information goes in partial fingerprings until revision
			// data can be added somewhere else
			PartialFingerPrints: PartialFingerPrints{
				CommitSha:     f.Commit,
				Email:         f.Email,
				CommitMessage: f.Message,
				Date:          f.Date,
				Author:        f.Author,
			},
			Properties: Properties{
				Tags: f.Tags,
			},
		}
		results = append(results, r)
	}
	return results
}

func getLocation(f Finding) []Locations {
	uri := f.File
	if f.SymlinkFile != "" {
		uri = f.SymlinkFile
	}
	return []Locations{
		{
			PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI: uri,
				},
				Region: Region{
					StartLine:   f.StartLine,
					EndLine:     f.EndLine,
					StartColumn: f.StartColumn,
					EndColumn:   f.EndColumn,
					Snippet: Snippet{
						Text: f.Secret,
					},
				},
			},
		},
	}
}

type PartialFingerPrints struct {
	CommitSha     string `json:"commitSha"`
	Email         string `json:"email"`
	Author        string `json:"author"`
	Date          string `json:"date"`
	CommitMessage string `json:"commitMessage"`
}

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
	ID          string           `json:"id"`
	Description ShortDescription `json:"shortDescription"`
}

type Driver struct {
	Name            string  `json:"name"`
	SemanticVersion string  `json:"semanticVersion"`
	InformationUri  string  `json:"informationUri"`
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
	StartLine   int     `json:"startLine"`
	StartColumn int     `json:"startColumn"`
	EndLine     int     `json:"endLine"`
	EndColumn   int     `json:"endColumn"`
	Snippet     Snippet `json:"snippet"`
}

type Snippet struct {
	Text string `json:"text"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type Locations struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type Properties struct {
	Tags []string `json:"tags"`
}

type Results struct {
	Message             Message     `json:"message"`
	RuleId              string      `json:"ruleId"`
	Locations           []Locations `json:"locations"`
	PartialFingerPrints `json:"partialFingerprints"`
	Properties          Properties `json:"properties"`
}

type Runs struct {
	Tool    Tool      `json:"tool"`
	Results []Results `json:"results"`
}

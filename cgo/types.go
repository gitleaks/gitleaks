package main

// FindingsPayload is a stable JSON payload returned to callers via C API.
// Keep this struct backward-compatible (only add fields).
type FindingsPayload struct {
	Findings []FindingPayload `json:"findings"`
}

type FindingPayload struct {
	RuleID      string   `json:"ruleId"`
	Description string   `json:"description,omitempty"`
	Match       string   `json:"match,omitempty"`
	Secret      string   `json:"secret,omitempty"`
	Tags        []string `json:"tags,omitempty"`

	// Start/end positions of the SECRET in bytes (0-based, end exclusive).
	SecretStart int `json:"secretStart"`
	SecretEnd   int `json:"secretEnd"`

	StartLine   int `json:"startLine,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`

	File   string `json:"file,omitempty"`
	Commit string `json:"commit,omitempty"`
}



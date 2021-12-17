package report

import (
	"encoding/json"
	"io"
)

func writeJson(findings []Finding, w io.WriteCloser) error {
	if len(findings) == 0 {
		findings = []Finding{}
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(findings)
}

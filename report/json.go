package report

import (
	"encoding/json"
	"io"
)

func writeJson(findings []Finding, w io.WriteCloser) error {
	if len(findings) == 0 {
		findings = []Finding{}
	}
	defer w.Close()

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(findings)
}

package report

import (
	"encoding/json"
	"io"

)

func writeJson(findings []Finding, w io.WriteCloser) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(findings)
}

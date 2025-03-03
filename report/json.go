package report

import (
	"encoding/json"
	"io"
)

type JsonReporter struct {
}

var _ Reporter = (*JsonReporter)(nil)

func (t *JsonReporter) Write(w io.WriteCloser, findings []Finding) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(findings)
}

package report

import (
	"io"
)

const (
	// https://cwe.mitre.org/data/definitions/798.html
	CWE              = "CWE-798"
	CWE_DESCRIPTION  = "Use of Hard-coded Credentials"
	StdoutReportPath = "-"
)

type Reporter interface {
	Write(w io.WriteCloser, findings []Finding) error
}
